package com.archer.nifi.processors;

/**
 * Test manuale (NON eseguito da `mvn test`, nessuna annotazione JUnit) da
 * lanciare a mano contro il router reale per verificare rapidamente la
 * connettività TLS dopo il fix Bouncy Castle. Uso:
 *   java -cp target/classes:target/test-classes:$(cat /tmp/cp.txt) \
 *        com.archer.nifi.processors.ArcherClientLiveSmokeTool <url> <password>
 */
public final class ArcherClientLiveSmokeTool {
    public static void main(String[] args) throws Exception {
        String url = args[0];
        String password = args[1];
        try (ArcherClient client = new ArcherClient(url, "user", true, java.time.Duration.ofSeconds(10))) {
            System.out.println("Connessione TLS + login in corso...");
            client.login(password);
            System.out.println("Login OK.");
            System.out.println(client.simInfo());
            ArcherClient.InboxPage inboxPage = client.inbox(0);
            System.out.println("Inbox summary: " + inboxPage.summary());
            System.out.println("Inbox entries: " + inboxPage.entries().size());
        }
    }
}
