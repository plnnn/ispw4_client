package lt.viko.eif.nychyporuk.ispw4_1;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) {

        final String ANSI_RESET = "\u001B[0m";
        final String ANSI_GREEN = "\u001B[32m";
        final String ANSI_PURPLE = "\u001B[35m";

        try (Socket socketMITM = new Socket("localhost", 1337);
             DataOutputStream dos = new DataOutputStream(socketMITM.getOutputStream())) {

            while (true) {
                // Generate RSA Key Pair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                //Enter a message
                System.out.print(ANSI_PURPLE + "Enter a message: " + ANSI_RESET);
                Scanner scanner = new Scanner(System.in);
                String message = scanner.nextLine();

                // Create Digital Signature
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(message.getBytes());
                byte[] digitalSignature = signature.sign();

                // Encode the signature and the public key for transmission
                String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
                String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

                // Send data to the MITM
                dos.writeUTF(encodedPublicKey);
                dos.writeUTF(encodedSignature);
                dos.writeUTF(message);

                System.out.println(ANSI_GREEN +
                        "Data was sent to the MITM.\n" +
                        ANSI_RESET);
            }
        } catch (NoSuchAlgorithmException | SignatureException
                 | IOException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}