import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class Transaction {
    public PublicKey sender;
    public PublicKey recipient;
    public String content;
    public byte[] signature;

    public Transaction(PublicKey sender, PublicKey recipient, String content, byte[] signature) {
        this.sender = sender;
        this.recipient = recipient;
        this.content = content;
        this.signature = signature;
    }

    public String getSenderPublicKey() {
        return Base64.getEncoder().encodeToString(sender.getEncoded());
    }

    public String getRecipientPublicKey() {
        return Base64.getEncoder().encodeToString(recipient.getEncoded());
    }

    @Override
    public String toString() {
        return "{\n" +
                "    \"sender_public_key\": \"" + getSenderPublicKey() + "\",\n" +
                "    \"recipient_public_key\": \"" + getRecipientPublicKey() + "\",\n" +
                "    \"content\": \"" + content + "\",\n" +
                "    \"signature\": \"" + Base64.getEncoder().encodeToString(signature) + "\"\n" +
                "}";
    }
}

class Block {
    public int index;
    public long timestamp;
    public String previousHash;
    public String hash;
    public int nonce;
    public List<Transaction> transactions;

    public Block(int index, long timestamp, String previousHash, List<Transaction> transactions) {
        this.index = index;
        this.timestamp = timestamp;
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.nonce = 0;
        this.hash = calculateHash();
    }

    public String calculateHash() {
        return HashUtil.applySha256(index + previousHash + timestamp + transactions.toString() + nonce);
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0');
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block mined: " + hash);
    }

    @Override
    public String toString() {
        return "{\n" +
                "    \"index\": " + index + ",\n" +
                "    \"previous_hash\": \"" + previousHash + "\",\n" +
                "    \"timestamp\": " + timestamp + ",\n" +
                "    \"transactions\": " + transactions.toString() + ",\n" +
                "    \"nonce\": " + nonce + ",\n" +
                "    \"hash\": \"" + hash + "\"\n" +
                "}";
    }
}

class Blockchain {
    public List<Block> chain;
    public int difficulty;

    public Blockchain(int difficulty) {
        this.difficulty = difficulty;
        this.chain = new ArrayList<>();
        chain.add(createGenesisBlock());
    }

    private Block createGenesisBlock() {
        return new Block(0, System.currentTimeMillis(), "0", new ArrayList<>());
    }

    public Block getLatestBlock() {
        return chain.get(chain.size() - 1);
    }

    public void addBlock(List<Transaction> transactions) {
        Block newBlock = new Block(chain.size(), System.currentTimeMillis(), getLatestBlock().hash, transactions);
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);
    }

    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block currentBlock = chain.get(i);
            Block previousBlock = chain.get(i - 1);

            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                System.out.println("Current Hashes not equal");
                return false;
            }
            if (!currentBlock.previousHash.equals(previousBlock.hash)) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        StringBuilder blockchainString = new StringBuilder();
        for (Block block : chain) {
            blockchainString.append(block.toString()).append("\n");
        }
        return blockchainString.toString();
    }
}

class HashUtil {
    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

public class PharmaSupplyChain {

    public static void main(String[] args) throws Exception {
        Blockchain blockchain = new Blockchain(4);

        KeyPair keyPair1 = generateKeyPair();
        KeyPair keyPair2 = generateKeyPair();
        KeyPair keyPair3 = generateKeyPair();

        // Create and sign transactions
        Transaction tx1 = new Transaction(keyPair1.getPublic(), keyPair2.getPublic(), "Drug shipment from Manufacturer to Distributor", signTransaction(keyPair1.getPrivate(), "Drug shipment from Manufacturer to Distributor"));
        Transaction tx2 = new Transaction(keyPair2.getPublic(), keyPair3.getPublic(), "Drug shipment from Distributor to Pharmacy", signTransaction(keyPair2.getPrivate(), "Drug shipment from Distributor to Pharmacy"));

        List<Transaction> transactions = new ArrayList<>();
        transactions.add(tx1);
        transactions.add(tx2);

        blockchain.addBlock(transactions);

        System.out.println("Blockchain after mining:");
        System.out.println(blockchain);

        System.out.println("Is blockchain valid? " + blockchain.isChainValid());
    }

    // Utility methods to generate key pairs and sign transactions
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.genKeyPair();
    }

    public static byte[] signTransaction(PrivateKey privateKey, String input) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(input.getBytes());
        return signature.sign();
    }
}
