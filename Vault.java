// Gagandeep Batra
// 11/3/2020

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.DestroyFailedException;

public class Vault {
    private static final int MAX_MESSAGE_SIZE = 1_000_000;
    private static final int ENCODED_KEY_SIZE = 24; // base-64 encoding of 128 bit key
    private static String user;

    // NOTE: If youre IDE does not support the use of the Console class, you can 
    // debug with a scanner.   You would want to test your program, though, once
    // you are done with the other testing, using the Console class. 
    private static boolean IDE_DEBUG = false;
    private static Scanner scanner;
    private static Console console;
    static {
        console = System.console();
        if (console == null) {
            System.err.println("No console available!");
            System.exit(-1);
        }
    }

    public static void main(String[] args) {
        if (!authenticate()) {
            System.out.println("Invalid username or password");
            System.exit(-1);
        }

        int choice = 0;
        while (choice != 7) {
            choice = displayMenu();
            switch (choice) {
                case 1: displayFile(); break;
                case 2: replaceFile(); break;
                case 3: changePassword(true); break;
                case 4: enrollNewUser(); break;
                case 5: exportFile(); break;
                case 6: importFile(); break;
            }
        }
    }

    private static void displayFile() {
        try (Scanner vault = new Scanner(new File("vault.txt"))){
            while (vault.hasNextLine()) {
                System.out.println(vault.nextLine());
            }
        }
        catch (FileNotFoundException e) {
            return;
        }
    }


    /**
     * Display the menu for the user.  
     * v2 change log
     * - we are using the console to get user input, instead of a scanner.
     *
     * @return the user's choice
     */
    private static int displayMenu() {
        System.out.println("1) Display file");
        System.out.println("2) Replace file");
        System.out.println("3) Change password");
        System.out.println("4) Add user");
        System.out.println("5) Export file");
        System.out.println("6) Import file");
        System.out.println("7) Quit");
        System.out.print("\nEnter your choice (1-7): ");
        return Integer.valueOf(console.readLine());
    }

    /**
     * OPTION 2
     *
     * Replace the contents of the vault file.
     * v2 change log
     * - The input from the user is obtained via the Console object.
     * - We gather the input in a char buffer, which is then cleared.
     *
     */
    private static void replaceFile() {
        System.out.println("Enter your message.  When you are done type enter by itself on a blank line");
        char[] message = new char[MAX_MESSAGE_SIZE];
        int size = 0;
        String line = console.readLine();
        try {
            while (!line.equals("")) {
                for (int i = 0; i < line.length(); i++) {
                    message[size++] = line.charAt(i);
                }
                message[size++] = '\n';
                line = console.readLine();
            }
        }
        catch(IndexOutOfBoundsException e) {
            clearArray(message);
            System.out.println("The vault input exceeded the maximum vault size.");
            System.exit(-1);
        }

        try (PrintWriter vault = new PrintWriter(new File("vault.txt"))){
            // NOTE: You should be careful to avoid a call to:
            // vault.print(message);
            // This will translate the CharBuffer to a String, which is something we want to avoid.
            for (int i = 0; i < size; i++) {
                vault.print(message[i]);
                message[i] = ' ';
            }
        }
        catch (FileNotFoundException e) {
            clearArray(message);
            System.out.println("Unable to update the vault." + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * OPTION 3
     *
     * Allow the user to change their password.
     * v2 change log
     * - We are now using a char array to store the typed password, and removing it 
     *   from memory when we are done.
     * - If the user has just authenticated, the parameter authenticationRequired can
     *   be set to false, so that they do not need to authenticate twice.
     *
     * @param authenticationRequired do we require authentication to change the password
     */
    private static void changePassword(boolean authenticationRequired) {
        if (!authenticationRequired || authenticate()) {
            char[] password = enterNewPassword();

            ArrayList<String> entries = new ArrayList<>();
            try (Scanner scUsers = new Scanner(new File("users.txt"))){
                while (scUsers.hasNextLine()) {
                    String line = scUsers.nextLine();
                    String[] tokens = line.split(":");
                    if (!tokens[0].equals(user)) {
                        entries.add(line);
                    }
                }
            }
            catch (FileNotFoundException e) {
                clearArray(password);
                System.out.println("Unable to update the password.");
                System.exit(-1);
            }

            try (PrintWriter pwUsers = new PrintWriter(new File("users.txt"))){
                for (String entry: entries) {
                    pwUsers.println(entry);
                }
                pwUsers.print(user);
                pwUsers.print(":");
                for (int i = 0; i < password.length; i++) {
                    pwUsers.print(password[i]);
                }
                clearArray(password);
                pwUsers.println(":F");
            }
            catch (FileNotFoundException e) {
                clearArray(password);
                System.out.println("Unable to update the password.");
                System.exit(-1);
            }
        }
    }

    /**
     * OPTION 4
     *
     * Enroll a new user.
     * v2 change log
     * - We use the new password routine to prompt the user for a password in
     *   a more secure fashion.  
     * - The contents of the memory containing this password are cleared when 
     *   it is no longer needed.
     * - We set a flag requiring the new user to change their password upon their 
     *   next login.
     */
    private static void enrollNewUser() {
        System.out.print("Enter a new username: ");
        String user = console.readLine();
        char[] password = enterNewPassword();

        boolean ok = true;
        ArrayList<String> entries = new ArrayList<>();
        try (Scanner scUsers = new Scanner(new File("users.txt")) ){
            while (ok && scUsers.hasNextLine()) {
                String line = scUsers.nextLine();
                String[] tokens = line.split(":");
                if (tokens[0].equals(user)) {
                    ok = false;
                }
                else {
                    entries.add(line);
                }
            }
        }
        catch (FileNotFoundException e) {
            System.out.println("Unable to update the users list.");
            ok = false;
        }

        if (ok) {
            try (PrintWriter pwUsers = new PrintWriter(new File("users.txt"))){
                for (String entry: entries) {
                    pwUsers.println(entry);
                }
                pwUsers.print(user + ":");
                for (int i = 0; i < password.length; i++) {
                    pwUsers.print(password[i]);
                }
                pwUsers.println(":T");
            }
            catch (FileNotFoundException e) {
                System.out.println("Error updating the users list.");
                System.exit(-1);
            }
        }
        clearArray(password);
    }

    /**
     * Validate the recipient certificate with the root
     * @param null
     * @return X509Certificate recipient
     */
    private static X509Certificate validateCertificate(){
        // Get email and filenames
        System.out.print("Enter the email address of the recipient: ");
        String email = console.readLine();
        System.out.print("Enter the filename of your certificate file: ");
        String myCertFileName = console.readLine();
        System.out.print("Enter the filename of the CA certificate file: ");
        String rootFileName = console.readLine();

        CertificateFactory certFactory;
        X509Certificate myCert;
        X509Certificate root;

        // Grab the certificates
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            myCert = (X509Certificate) certFactory.generateCertificate(new FileInputStream(myCertFileName));
            root = (X509Certificate) certFactory.generateCertificate(new FileInputStream(rootFileName));
        }
        catch (FileNotFoundException | CertificateException e){
            System.out.println("Error generating the certificates");
            return null;
        }

        // Validate the following:

        // The constraints are appropriate for the CACert.
        assert root != null;
        if(root.getBasicConstraints() == -1)
            return null;

        // The subjects for the certificates are correct.
        String caSubject = root.getSubjectX500Principal().toString();
        String caEmail = caSubject.substring(caSubject.indexOf("=")+1, caSubject.indexOf(","));
        String recipientSubject = myCert.getSubjectX500Principal().toString();
        String recipientEmail = recipientSubject.substring(recipientSubject.indexOf("=")+1, recipientSubject.indexOf(","));
        if(!caEmail.equals("support@cacert.org") || !recipientEmail.equals(email))
            return null;

        // The current time falls in the period of validity for both certificates
        try {
            myCert.checkValidity();
            root.checkValidity();
        }
        catch (CertificateNotYetValidException |  CertificateExpiredException e){
            System.out.println("Error validating the certificates");
            return null;
        }

        // Validate the signatures on both certificates
        try {
            myCert.verify(root.getPublicKey());
        }
        catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.out.println("Error verifying the certificates");
            return null;
        }

        return myCert;
    }

    /**
     * OPTION 5
     *
     * Export the contents of the vault file to an encrypted share.txt file.
     *
     * v2 change log
     * - We create a symmetric key to encrypt the contents of the vault.  This key is base-64 encoded and 
     *   written to key.txt
     * - We write the initialization vector and the base-64 encoded, encrypted message to vault.txt
     *
     * @return
     */
    private static void exportFile() {
        X509Certificate myCert = validateCertificate();

        // Certificate tests did not pass
        if(myCert == null) {
            System.out.println("Unable to validate certificates");
            return;
        }

        // Certificates have passed tests, generate base-64 encoded, wrapped AES key
        SecretKey aesSecret = null;
        Cipher rsaCipher;
        Cipher cipher = null;
        byte[] bSecret = null;
        try {
            aesSecret = KeyGenerator.getInstance("AES").generateKey();
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesSecret);
            rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.WRAP_MODE, myCert.getPublicKey());
            bSecret = Base64.getEncoder().encode(rsaCipher.wrap(aesSecret));
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e){
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }

        try {
            assert aesSecret != null;
            aesSecret.destroy();
        }
        catch (DestroyFailedException e) {
            // Not all implementations have this method defined.
        }

        // Write out key.txt file
        try (PrintWriter key = new PrintWriter(new File("key.txt"))){
            // Write IV, clearing memory as appropriate
            for (int i = 0; i < bSecret.length; i++) {
                key.print((char) bSecret[i]);
                bSecret[i] = 0;
            }
            key.println();
        }
        catch (FileNotFoundException e) {
            System.out.println("Unable to export the file.");
            System.exit(-1);
        }

        // Read the vault
        char[] message = new char[MAX_MESSAGE_SIZE];
        int size = 0;
        try (Scanner vault = new Scanner(new File("vault.txt"))){
            if (vault != null) {
                while (vault.hasNextLine()) {
                    String line = vault.nextLine();
                    for (int i = 0; i < line.length(); i++) {
                        message[size++] = line.charAt(i);
                    }
                    message[size++] = '\n';
                }
            }
        }
        catch (IndexOutOfBoundsException e) {
            clearArray(message);
            System.out.println("The vault file has exceeded the maximum size.  Unable to export");
            return;
        }
        catch (FileNotFoundException e) {
            // Continue with a blank message to be decoded.
        }

        // Get encoded ciphertext
        byte[] plaintext = toByteArray(message, size);
        clearArray(message);
        String encodedCipherText = null;
        try {
            encodedCipherText = Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
        }
        catch (BadPaddingException | IllegalBlockSizeException e) {
            // Note that these exceptions should only occur when decrypting
            clearArray(plaintext);
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }
        clearArray(plaintext);

        // Write ciphertext to file
        try (PrintWriter share = new PrintWriter(new File("share.txt"))){
            // Write IV
            // Note: To test ECB, comment out next line
            share.println(Base64.getEncoder().encodeToString(cipher.getIV()));

            // Write ciphertext
            share.println(encodedCipherText);
        }
        catch (FileNotFoundException e) {
            System.out.println("Unable to update the shared file.");
            System.exit(-1);
        }
    }

    /**
     * Decrypt wrapped key
     * @param byte[] wrappedKey
     * @return SecretKey
     */
    private static SecretKey privateKey(byte[] wrappedKey){
        System.out.print("Enter the filename of the private key file: ");
        String keyFile = console.readLine();

        // read encrypted private key from PKCS8 file
        byte[] encryptedPrivKeyBytes = null;
        EncryptedPrivateKeyInfo encryptPrivKeyInfo = null;
        try {
            File privKeyFile = new File(keyFile);
            DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
            encryptedPrivKeyBytes = new byte[(int) privKeyFile.length()];
            dis.read(encryptedPrivKeyBytes);
            dis.close();

            // Get information about how the Key is stored in the File - we will use this
            // object to retrieve the algorithm used to encrypt the key and parameters
            // used by the algorithm
            encryptPrivKeyInfo = new EncryptedPrivateKeyInfo(encryptedPrivKeyBytes);
        } catch (IOException e) {
            System.out.println("Error reading file");
            return null;
        }

        // Prompt user for encryption password.
        // Collect user password as char array (using the
        // "readPassword" method from above)
        char[] passdata = console.readPassword("Enter encryption password: ");
        if(passdata == null) {
            System.out.println("Error reading password");
            return null;
        }

        // Convert the password to a secret key, using a PBE key factory.
        // This is the same secret key that was used to encrypt the key in
        // the PKCS 8 file
        PBEKeySpec pbeKeySpec = null;
        SecretKey pbeKey = null;
        try {
            pbeKeySpec = new PBEKeySpec(passdata);
            Arrays.fill(passdata, ' '); // Clear data in password array so that it does not stay in memory
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance(encryptPrivKeyInfo.getAlgName());
            pbeKey = keyFac.generateSecret(pbeKeySpec);
            pbeKeySpec.clearPassword(); // Clears the internal copy of the password
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Arrays.fill(passdata, ' ');
            pbeKeySpec.clearPassword();
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }

        // Create a Cipher object that can unwrap the encrypted private key. We
        // initialize this cipher with the key derived from the password, and the
        // algorithms retrieved from the pkcs8 file containing the encrypted key
        SecretKey recoveredKey = null;
        try {
            Cipher cipher = Cipher.getInstance(encryptPrivKeyInfo.getAlgName());
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptPrivKeyInfo.getAlgParameters());
            // Extract the unencrypted KeySpec object from the encrypted data
            PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(encryptPrivKeyInfo.getKeySpec(cipher));
            // Once we have the KeySpec, we can generate a RSAPrivateKey object in the normal way...
            Cipher rsaCipher2 = Cipher.getInstance("RSA");
            rsaCipher2.init(Cipher.UNWRAP_MODE, privKey);
            recoveredKey = (SecretKey) rsaCipher2.unwrap(Base64.getDecoder().decode(wrappedKey), "AES", Cipher.SECRET_KEY);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | InvalidKeySpecException e) {
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }

        return recoveredKey;
    }

    /**
     * Import the share.txt file
     * v2 change log
     * - the file now contains encrypted ciphertext
     * @throws
     */
    private static void importFile() {
        // Get wrapped key
        String wrappedKey;
        try (Scanner key = new Scanner(new File("key.txt"))){
            wrappedKey = key.nextLine();
        }
        catch (FileNotFoundException e) {
            System.out.println("Error importing file");
            return;
        }

        // Decrypt wrapped key
        SecretKey secret = privateKey(wrappedKey.getBytes());
        // if secret is null, there was an error unwrapping the key
        if(secret == null) {
            System.out.println("Error importing file");
            return;
        }

        // Read the share.txt file
        byte[] iv = null;
        byte[] ciphertext = null;
        try (Scanner share = new Scanner(new File("share.txt"))){
            // Note to test ECB, comment out next line
            iv = Base64.getDecoder().decode(share.nextLine());
            ciphertext = Base64.getDecoder().decode(share.nextLine());
        }
        catch (FileNotFoundException e) {
            return;
        }

        // Initialize the cipher
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            // To test ECB use next lines instead
            //cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            //cipher.init(Cipher.DECRYPT_MODE, secret);
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // To test ECB, remove InvalidAlgorithmParameterException:
            //catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException  e) {
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }

        try {
            secret.destroy();
        }
        catch (DestroyFailedException e) {
            // destroy may not be implemented
        }

        byte[] plaintext = null;
        try {
            plaintext = cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e1) {
            clearArray(plaintext);
            System.out.println("Error importing file.");
            System.exit(-1);
        }

        if (plaintext.length > MAX_MESSAGE_SIZE) {
            System.out.println("Import file exceeded max vault size.");
            System.exit(-1);
        }

        try (PrintWriter vault = new PrintWriter(new File("vault.txt"))){
            for (int i = 0; i < plaintext.length; i++) {
                vault.print((char) plaintext[i]);
                plaintext[i] = ' ';
            }
        }
        catch (FileNotFoundException e) {
            System.out.println("Unable to write to the vault file.");
        }
    }

    /**
     * Authenticate the user.
     * v2 change log
     * - We are using the console to mask the characters that the user types.  
     * - We are ensuring that the password that is typed in is removed from memory when it is no
     *   longer needed.
     * - We prompt the user to change their password if they successfully authenticate, and the change 
     *   password flag is set
     *
     * @return whether the user was authenticated
     */
    private static boolean authenticate() {
        System.out.print("Enter your username: ");
        user = console.readLine();
        char[] password = console.readPassword("Enter your password: ");

        boolean result = false;
        try (Scanner users = new Scanner(new File("users.txt"))){
            while (!result && users.hasNextLine()) {
                String[] tokens = users.nextLine().split(":");
                if (tokens.length == 3 && tokens[0].equals(user) &&
                        Arrays.equals(tokens[1].toCharArray(), password)) {

                    if (tokens[2].equals("T")) {
                        System.out.println("You are required to change your password the first time you log in.");
                        changePassword(false);
                    }

                    result = true;
                }
            }
        }
        catch (Exception e) {
            System.err.println("An error occurred during authentication");
            System.exit(-1);
        }
        clearArray(password);
        return result;
    }


    /**
     * Prompt the user to enter a new password.  The password will be 
     * entered twice, and we will ensure that the passwords match.  We
     * also ensure that the password does not contain a ':' character
     *
     * @return the new password
     */
    private static char[] enterNewPassword() {
        char[] password1 = null;
        boolean ok = false;
        while (!ok) {
            password1 = console.readPassword("Enter a new password: ");

            ok = true;
            for (int i = 0; !ok && i < password1.length; i++) {
                if (password1[i] == ':') {
                    System.out.println("The password cannot contain a colon (:).");
                    ok = false;
                }
            }
            if (ok) {
                char[] password2 = console.readPassword("Renter a new password: ");
                if (!Arrays.equals(password1, password2)) {
                    System.out.println("The passwords do not match.");
                    ok = false;
                }
                clearArray(password2);
            }
            if (!ok) {
                clearArray(password1);
            }
        }
        return password1;
    }

    /**
     * Clear the contents of the array 
     * @param array An array containing sensitive information
     */
    private static void clearArray(char[] array) {
        if (array == null) return;
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
    }

    /**
     * Clear the contents of a byte array 
     * @param array An array containing sensitive information
     */
    private static void clearArray(byte[] array) {
        if (array == null) return;
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
    }

    /**
     * Convert a CharBuffer to a byte array
     *
     * @param array The CharBuffer with contents to be converted
     */
    private static byte[] toByteArray(char[] array, int size) {
        byte[] retArray = new byte[size];
        for (int i = 0; i < size; i++) {
            retArray[i] = (byte) array[i];
        }
        return retArray;
    }
}
