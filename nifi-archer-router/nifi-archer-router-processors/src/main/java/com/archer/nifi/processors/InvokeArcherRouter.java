package com.archer.nifi.processors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.TriggerSerially;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnStopped;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.flowfile.attributes.CoreAttributes;
import org.apache.nifi.flowfile.attributes.FragmentAttributes;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.schema.access.SchemaNotFoundException;
import org.apache.nifi.serialization.RecordSetWriter;
import org.apache.nifi.serialization.RecordSetWriterFactory;
import org.apache.nifi.serialization.SimpleRecordSchema;
import org.apache.nifi.serialization.WriteResult;
import org.apache.nifi.serialization.record.ListRecordSet;
import org.apache.nifi.serialization.record.MapRecord;
import org.apache.nifi.serialization.record.Record;
import org.apache.nifi.serialization.record.RecordField;
import org.apache.nifi.serialization.record.RecordFieldType;
import org.apache.nifi.serialization.record.RecordSchema;
import org.apache.nifi.serialization.record.RecordSet;
import org.apache.nifi.stream.io.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * NiFi processor that reproduces, without going through a browser, the
 * management-panel protocol of TP-Link Archer routers with a 4G/5G SIM in
 * "GDPR encrypt" configuration (tested on the Archer NX200): login (RSA
 * 512-bit + AES-128-CBC handshake), reading the SMS inbox, sending an SMS,
 * reading SIM/network/data-usage info.
 *
 * <p>See PROTOCOL.md in the repository for the full protocol description,
 * reverse-engineered from the router's own WebUI.</p>
 *
 * <p><b>Session handling:</b> the router allows only one administrative
 * session at a time, and the embedded webserver does not take kindly to
 * back-to-back logins (see PROTOCOL.md §6.1). This processor therefore
 * authenticates lazily and keeps the session (cookie + CSRF token) cached
 * across executions instead of logging in on every trigger: a login only
 * happens on the first run, when the Router URL/Username/Trust-all-certs/
 * Connection-timeout properties change, or after the cached session turns
 * out to be no longer valid. That last case is detected from an HTTP
 * non-200 on a post-login data call (typically because something else -
 * e.g. someone logging into the WebUI from a browser - took over the
 * router's single session slot, the same as clicking "force logout of the
 * other device" in the GUI); the processor then re-authenticates and
 * retries automatically for the read-only operations (INBOX, SIM_INFO).
 * SEND_SMS is deliberately <b>not</b> auto-retried at this level: if the
 * session drops while polling for the send outcome, the SMS itself may
 * already have gone out, so retrying the whole operation could send it
 * twice; the processor re-authenticates the cached session for next time
 * but still routes that FlowFile to failure. {@code @TriggerSerially}
 * ensures this cached state is never touched by two invocations at once,
 * regardless of a "Concurrent Tasks" setting greater than 1 - which
 * wouldn't help anyway, since the router itself only ever allows one
 * session. The router does not expose a real CSRF header/cookie: this
 * processor recovers it, after login, embedded server-side in the home
 * page's HTML.</p>
 */
@TriggerSerially
@Tags({"tplink", "archer", "router", "sms", "iot", "lte", "5g"})
@CapabilityDescription("Authenticates against the management panel of a TP-Link Archer router with a "
        + "4G/5G SIM (e.g. Archer NX200, \"GDPR encrypt\" firmware) by reproducing the WebUI protocol "
        + "(RSA + AES, without using a browser), then performs one of: reading the SMS inbox, sending "
        + "an SMS, reading SIM/network/data-usage information. The INBOX result can optionally be "
        + "written with a Record Writer; SEND_SMS and SIM_INFO are always written as JSON.")
@WritesAttributes({
        @WritesAttribute(attribute = "mime.type", description = "Set on the success FlowFile: application/json, or the configured Record Writer's mime type for INBOX."),
        @WritesAttribute(attribute = "archer.operation", description = "The operation that was performed (INBOX, SEND_SMS, SIM_INFO)."),
        @WritesAttribute(attribute = "archer.inbox.total", description = "INBOX only: total number of SMS in the inbox, as reported by the router."),
        @WritesAttribute(attribute = "archer.inbox.unread", description = "INBOX only: number of unread SMS, as reported by the router."),
        @WritesAttribute(attribute = "archer.inbox.page", description = "INBOX only: the page number that was read (same as the \"Inbox page\" property)."),
        @WritesAttribute(attribute = "archer.inbox.amountPerPage", description = "INBOX only: how many messages the router returns per page."),
        @WritesAttribute(attribute = "fragment.identifier", description = "INBOX only: groups pages of the same inbox listing together, for a later MergeContent (Defragment). Copied from the incoming FlowFile's own fragment.identifier when present, otherwise a new UUID."),
        @WritesAttribute(attribute = "fragment.index", description = "INBOX only: the requested inbox page number, as a fragment index."),
        @WritesAttribute(attribute = "fragment.count", description = "INBOX only: total number of pages the inbox spans, computed from archer.inbox.total / archer.inbox.amountPerPage."),
        @WritesAttribute(attribute = "record.count", description = "INBOX only, when a Record Writer is configured: number of records written.")
})
@InputRequirement(InputRequirement.Requirement.INPUT_ALLOWED)
public class InvokeArcherRouter extends AbstractProcessor {

    static final AllowableValue OP_INBOX = new AllowableValue("INBOX", "Read SMS inbox",
            "Lists received SMS messages (DEV2_LTE_SMS_RECVMSGBOX/RECVMSGENTRY).");
    static final AllowableValue OP_SEND_SMS = new AllowableValue("SEND_SMS", "Send SMS",
            "Sends an SMS (DEV2_LTE_SMS_SENDNEWMSG) to the number given in \"Recipient Number\".");
    static final AllowableValue OP_SIM_INFO = new AllowableValue("SIM_INFO", "SIM/network/data-usage info",
            "ICCID/IMSI, network status, assigned IP, total and today's data usage.");

    static final PropertyDescriptor ROUTER_URL = new PropertyDescriptor.Builder()
            .name("router-url")
            .displayName("Router URL")
            .description("Base URL of the router's management panel, e.g. https://192.168.10.1")
            .required(true)
            .defaultValue("https://192.168.10.1")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.URL_VALIDATOR)
            .build();

    static final PropertyDescriptor USERNAME = new PropertyDescriptor.Builder()
            .name("username")
            .displayName("Username")
            .description("Login username. On models with an admin/user distinction (like the Archer "
                    + "NX200) and no username field visible in the GUI, it is normally \"user\".")
            .required(true)
            .defaultValue("user")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .build();

    static final PropertyDescriptor PASSWORD = new PropertyDescriptor.Builder()
            .name("password")
            .displayName("Password")
            .description("Password for the router's management panel.")
            .required(true)
            .sensitive(true)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .build();

    static final PropertyDescriptor OPERATION = new PropertyDescriptor.Builder()
            .name("operation")
            .displayName("Operation")
            .description("The operation to perform against the router.")
            .required(true)
            .allowableValues(OP_INBOX, OP_SEND_SMS, OP_SIM_INFO)
            .defaultValue(OP_INBOX.getValue())
            .build();

    static final PropertyDescriptor INBOX_PAGE = new PropertyDescriptor.Builder()
            .name("inbox-page")
            .displayName("Inbox page")
            .description("0-based page number of the SMS inbox to read. Only used with the \""
                    + OP_INBOX.getDisplayName() + "\" operation.")
            .required(true)
            .defaultValue("0")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_NEGATIVE_INTEGER_VALIDATOR)
            .build();

    static final PropertyDescriptor RECORD_WRITER = new PropertyDescriptor.Builder()
            .name("record-writer")
            .displayName("Record Writer")
            .description("Only used with the \"" + OP_INBOX.getDisplayName() + "\" operation. When set, "
                    + "each SMS is written as a record (fixed schema: index, from, content, receivedTime, "
                    + "unread — all STRING) using this writer, instead of the default JSON array. Lets "
                    + "the inbox be produced directly as CSV/Avro/etc. Per-page metadata (total/unread "
                    + "count, page number) is written as FlowFile attributes either way, not as fields.")
            .required(false)
            .identifiesControllerService(RecordSetWriterFactory.class)
            .build();

    static final PropertyDescriptor PHONE_NUMBER = new PropertyDescriptor.Builder()
            .name("phone-number")
            .displayName("Recipient number")
            .description("Recipient phone number, e.g. +393331234567. Required with the \""
                    + OP_SEND_SMS.getDisplayName() + "\" operation.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .build();

    static final PropertyDescriptor MESSAGE_TEXT = new PropertyDescriptor.Builder()
            .name("message-text")
            .displayName("Message text")
            .description("Text of the SMS to send. If not set, the content of the incoming FlowFile "
                    + "is used instead (as UTF-8 text). Required (here or via the FlowFile content) "
                    + "with the \"" + OP_SEND_SMS.getDisplayName() + "\" operation.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    static final PropertyDescriptor WAIT_FOR_SEND_RESULT = new PropertyDescriptor.Builder()
            .name("wait-for-send-result")
            .displayName("Wait for send result")
            .description("If true, after sending, polls the router (up to 20s) until it reports a "
                    + "definitive outcome (sendResult other than \"in progress\"), instead of returning "
                    + "just the enqueue acknowledgement.")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();

    static final PropertyDescriptor TRUST_ALL_CERTS = new PropertyDescriptor.Builder()
            .name("trust-all-certs")
            .displayName("Trust all TLS certificates")
            .description("Routers in this series use a self-signed TLS certificate with no subject/SAN "
                    + "at all on the management interface: with this option set to \"true\" (default) "
                    + "the processor verifies neither the trust chain nor the hostname. Leave it at "
                    + "\"false\" only if a valid custom certificate has been installed.")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();

    static final PropertyDescriptor CONNECT_TIMEOUT = new PropertyDescriptor.Builder()
            .name("connect-timeout")
            .displayName("Connection timeout")
            .required(true)
            .defaultValue("10 sec")
            .addValidator(StandardValidators.TIME_PERIOD_VALIDATOR)
            .build();

    static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("FlowFile carrying the operation's result on success.")
            .build();

    static final Relationship REL_ORIGINAL = new Relationship.Builder()
            .name("original")
            .description("The incoming FlowFile (if any), unchanged, after a successful execution.")
            .build();

    static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("The incoming FlowFile (if any) on login or router-call failure.")
            .build();

    private static final List<PropertyDescriptor> PROPERTIES = List.of(
            ROUTER_URL, USERNAME, PASSWORD, OPERATION, INBOX_PAGE, RECORD_WRITER, PHONE_NUMBER,
            MESSAGE_TEXT, WAIT_FOR_SEND_RESULT, TRUST_ALL_CERTS, CONNECT_TIMEOUT
    );

    /** Fixed, explicit schema used for the INBOX operation when a Record Writer is configured. */
    private static final RecordSchema INBOX_RECORD_SCHEMA = new SimpleRecordSchema(List.of(
            new RecordField("index", RecordFieldType.STRING.getDataType()),
            new RecordField("from", RecordFieldType.STRING.getDataType()),
            new RecordField("content", RecordFieldType.STRING.getDataType()),
            new RecordField("receivedTime", RecordFieldType.STRING.getDataType()),
            new RecordField("unread", RecordFieldType.STRING.getDataType())
    ));

    private static final Set<Relationship> RELATIONSHIPS;

    static {
        Set<Relationship> rels = new HashSet<>();
        rels.add(REL_SUCCESS);
        rels.add(REL_ORIGINAL);
        rels.add(REL_FAILURE);
        RELATIONSHIPS = Collections.unmodifiableSet(rels);
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Cached, already-authenticated client, reused across {@link #onTrigger}
     * invocations instead of logging in every time (see the class-level
     * javadoc on session handling). {@code @TriggerSerially} guarantees only
     * one invocation touches these fields at a time; {@code volatile} is
     * still needed because successive invocations are not guaranteed to run
     * on the same thread.
     */
    private volatile ArcherClient cachedClient;
    /** Identifies which Router URL/Username/Trust-all-certs/timeout the cached client was built for. */
    private volatile String cachedSessionKey;

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return PROPERTIES;
    }

    @Override
    public Set<Relationship> getRelationships() {
        return RELATIONSHIPS;
    }

    @OnStopped
    public void discardCachedSession() {
        if (cachedClient != null) {
            cachedClient.close();
        }
        cachedClient = null;
        cachedSessionKey = null;
    }

    @Override
    public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
        FlowFile input = session.get();
        boolean hasInput = input != null;

        String url = context.getProperty(ROUTER_URL).evaluateAttributeExpressions(input).getValue();
        String username = context.getProperty(USERNAME).evaluateAttributeExpressions(input).getValue();
        String password = context.getProperty(PASSWORD).getValue();
        String operation = context.getProperty(OPERATION).getValue();
        boolean trustAll = context.getProperty(TRUST_ALL_CERTS).asBoolean();
        Duration timeout = Duration.ofMillis(
                context.getProperty(CONNECT_TIMEOUT).asTimePeriod(TimeUnit.MILLISECONDS));
        String sessionKey = String.join("|", url, username, String.valueOf(trustAll), timeout.toString());

        try {
            ArcherClient client = sessionKey.equals(cachedSessionKey) ? cachedClient : null;
            if (client == null) {
                client = new ArcherClient(url, username, trustAll, timeout);
                client.login(password);
                cachedClient = client;
                cachedSessionKey = sessionKey;
            }

            try {
                runOperation(context, session, input, client, operation, url);
            } catch (ArcherClient.SessionExpiredException e) {
                if (OP_SEND_SMS.getValue().equals(operation)) {
                    // Do NOT retry: the SMS may already have been sent before the
                    // session dropped (see class-level javadoc). Re-authenticate so
                    // the next trigger starts from a valid session, but still fail
                    // this FlowFile.
                    getLogger().warn("Archer session no longer valid while sending an SMS; "
                            + "re-authenticating for next time but not retrying this send "
                            + "(the message may already be on its way)", e);
                    cachedClient = null;
                    cachedSessionKey = null;
                    ArcherClient fresh = new ArcherClient(url, username, trustAll, timeout);
                    fresh.login(password);
                    cachedClient = fresh;
                    cachedSessionKey = sessionKey;
                    throw e;
                }
                getLogger().warn("Archer session no longer valid ({}); re-authenticating and retrying once", e.getMessage());
                client = new ArcherClient(url, username, trustAll, timeout);
                client.login(password);
                cachedClient = client;
                cachedSessionKey = sessionKey;
                runOperation(context, session, input, client, operation, url);
            }

        } catch (Exception e) {
            if (!(e instanceof ArcherClient.SessionExpiredException)) {
                // A stale/unauthenticated client is worse than none: drop it so the
                // next trigger starts with a fresh login instead of repeating the
                // same failure. (SessionExpiredException on SEND_SMS is handled
                // above and already leaves a freshly-logged-in client in place.)
                cachedClient = null;
                cachedSessionKey = null;
            }
            getLogger().error("Call to the Archer router ({}) failed", new Object[]{operation}, e);
            if (hasInput) {
                session.transfer(session.penalize(input), REL_FAILURE);
            } else {
                // No incoming FlowFile to route to failure: log it and let the next
                // scheduled run retry (useful when the processor is used as a source,
                // scheduled at an interval, with no incoming queue).
                context.yield();
            }
        }
    }

    /** Runs the configured operation against an already-authenticated client and writes its result. */
    private void runOperation(ProcessContext context, ProcessSession session, FlowFile input,
                               ArcherClient client, String operation, String url) throws Exception {
        if (OP_INBOX.getValue().equals(operation)) {
            int page = context.getProperty(INBOX_PAGE).evaluateAttributeExpressions(input).asInteger();
            ArcherClient.InboxPage inboxPage = client.inbox(page);
            writeInboxResult(context, session, input, inboxPage, page, url, operation);
            return;
        }

        Object result;
        if (OP_SEND_SMS.getValue().equals(operation)) {
            String phone = context.getProperty(PHONE_NUMBER).evaluateAttributeExpressions(input).getValue();
            if (phone == null || phone.isBlank()) {
                throw new ProcessException("Property \"" + PHONE_NUMBER.getDisplayName()
                        + "\" is required for the " + OP_SEND_SMS.getDisplayName() + " operation");
            }
            String text = resolveMessageText(context, session, input);
            boolean wait = context.getProperty(WAIT_FOR_SEND_RESULT).asBoolean();
            result = client.sendSms(phone, text, wait, Duration.ofSeconds(20));

        } else if (OP_SIM_INFO.getValue().equals(operation)) {
            result = client.simInfo();

        } else {
            throw new ProcessException("Unsupported operation: " + operation);
        }

        writeJsonResult(session, input, result, url, operation);
    }

    /** SEND_SMS / SIM_INFO: always written as pretty-printed JSON, unchanged from before. */
    private void writeJsonResult(ProcessSession session, FlowFile input, Object result, String url, String operation) throws IOException {
        boolean hasInput = input != null;
        FlowFile out = hasInput ? session.create(input) : session.create();
        byte[] json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(result);
        out = session.write(out, outStream -> outStream.write(json));
        out = session.putAttribute(out, CoreAttributes.MIME_TYPE.key(), "application/json");
        out = session.putAttribute(out, "archer.operation", operation);
        session.transfer(out, REL_SUCCESS);

        if (hasInput) {
            session.transfer(input, REL_ORIGINAL);
        }
        session.getProvenanceReporter().create(out, url);
    }

    /**
     * INBOX: written either via the configured Record Writer (fixed schema,
     * see {@link #INBOX_RECORD_SCHEMA}) or, if none is set, as a plain JSON
     * array of the same fields — plus, either way, per-page metadata and
     * standard {@code fragment.*} attributes (see the class-level
     * {@code @WritesAttributes}) so that pages read across multiple
     * executions can later be reassembled with MergeContent (Defragment).
     */
    private void writeInboxResult(ProcessContext context, ProcessSession session, FlowFile input,
                                   ArcherClient.InboxPage inboxPage, int page, String url, String operation)
            throws IOException, SchemaNotFoundException {
        boolean hasInput = input != null;
        JsonNode entries = inboxPage.entries();
        JsonNode summary = inboxPage.summary();

        int totalNumber = summary.path("totalNumber").asInt(-1);
        int unreadNumber = summary.path("unreadNumber").asInt(-1);
        int amountPerPage = summary.path("amountPerPage").asInt(-1);
        int fragmentCount = (totalNumber >= 0 && amountPerPage > 0)
                ? (int) Math.ceil(totalNumber / (double) amountPerPage)
                : 1;
        String fragmentId = hasInput && input.getAttribute(FragmentAttributes.FRAGMENT_ID.key()) != null
                ? input.getAttribute(FragmentAttributes.FRAGMENT_ID.key())
                : UUID.randomUUID().toString();

        RecordSetWriterFactory writerFactory = context.getProperty(RECORD_WRITER).isSet()
                ? context.getProperty(RECORD_WRITER).asControllerService(RecordSetWriterFactory.class)
                : null;

        FlowFile out = hasInput ? session.create(input) : session.create();

        if (writerFactory != null) {
            List<Record> records = new ArrayList<>();
            for (JsonNode entry : entries) {
                Map<String, Object> values = new LinkedHashMap<>();
                values.put("index", textOrNull(entry, "index"));
                values.put("from", textOrNull(entry, "from"));
                values.put("content", textOrNull(entry, "content"));
                values.put("receivedTime", textOrNull(entry, "receivedTime"));
                values.put("unread", textOrNull(entry, "unread"));
                records.add(new MapRecord(INBOX_RECORD_SCHEMA, values));
            }
            RecordSet recordSet = new ListRecordSet(INBOX_RECORD_SCHEMA, records);

            AtomicReference<WriteResult> writeResultRef = new AtomicReference<>();
            AtomicReference<String> mimeTypeRef = new AtomicReference<>();
            final FlowFile flowFileForSchema = out;
            out = session.write(out, rawOut -> {
                try (RecordSetWriter writer = writerFactory.createWriter(getLogger(), INBOX_RECORD_SCHEMA, rawOut, flowFileForSchema)) {
                    writeResultRef.set(writer.write(recordSet));
                    mimeTypeRef.set(writer.getMimeType());
                } catch (SchemaNotFoundException e) {
                    throw new IOException("Record Writer could not resolve the schema", e);
                }
            });
            out = session.putAllAttributes(out, writeResultRef.get().getAttributes());
            out = session.putAttribute(out, CoreAttributes.MIME_TYPE.key(), mimeTypeRef.get());
            out = session.putAttribute(out, "record.count", String.valueOf(writeResultRef.get().getRecordCount()));
        } else {
            byte[] json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(entries);
            out = session.write(out, outStream -> outStream.write(json));
            out = session.putAttribute(out, CoreAttributes.MIME_TYPE.key(), "application/json");
        }

        out = session.putAttribute(out, "archer.operation", operation);
        if (totalNumber >= 0) {
            out = session.putAttribute(out, "archer.inbox.total", String.valueOf(totalNumber));
        }
        if (unreadNumber >= 0) {
            out = session.putAttribute(out, "archer.inbox.unread", String.valueOf(unreadNumber));
        }
        out = session.putAttribute(out, "archer.inbox.page", String.valueOf(page));
        if (amountPerPage >= 0) {
            out = session.putAttribute(out, "archer.inbox.amountPerPage", String.valueOf(amountPerPage));
        }
        out = session.putAttribute(out, FragmentAttributes.FRAGMENT_ID.key(), fragmentId);
        out = session.putAttribute(out, FragmentAttributes.FRAGMENT_INDEX.key(), String.valueOf(page));
        out = session.putAttribute(out, FragmentAttributes.FRAGMENT_COUNT.key(), String.valueOf(fragmentCount));

        session.transfer(out, REL_SUCCESS);
        if (hasInput) {
            session.transfer(input, REL_ORIGINAL);
        }
        session.getProvenanceReporter().create(out, url);
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }

    /** Text of the message to send: from the property, otherwise from the incoming FlowFile's content. */
    private String resolveMessageText(ProcessContext context, ProcessSession session, FlowFile input) throws ProcessException {
        String fromProperty = context.getProperty(MESSAGE_TEXT).evaluateAttributeExpressions(input).getValue();
        if (fromProperty != null && !fromProperty.isBlank()) {
            return fromProperty;
        }
        if (input == null) {
            throw new ProcessException("Property \"" + MESSAGE_TEXT.getDisplayName()
                    + "\" is not set and there is no incoming FlowFile to read the text from.");
        }
        final byte[] buffer = new byte[(int) input.getSize()];
        session.read(input, (InputStream in) -> {
            try {
                StreamUtils.fillBuffer(in, buffer, true);
            } catch (IOException e) {
                throw new ProcessException("Failed to read the FlowFile's content", e);
            }
        });
        String text = new String(buffer, StandardCharsets.UTF_8);
        if (text.isBlank()) {
            throw new ProcessException("Property \"" + MESSAGE_TEXT.getDisplayName()
                    + "\" is not set and the FlowFile's content is empty.");
        }
        return text;
    }
}
