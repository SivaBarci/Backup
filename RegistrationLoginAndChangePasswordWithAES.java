import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

public class RegistrationLoginAndChangePasswordWithAES {
    static Scanner sc = new Scanner(System.in);
    private static final String SECRET_KEY = "secretKey@123";

    private static final String SALT = "random_text_for_more_safety";

    public static void main(String[] args) throws Exception {
        String logFileName = "LogDetailsAES.txt";
        createFile(logFileName);
        while(true) {
            System.out.println("Choose an option: ");
            System.out.println("1: Registration");
            System.out.println("2: User login");
            System.out.println("3: Admin login");
            System.out.println("4: Change password");
            System.out.println("0: Exit");
            System.out.print("=> ");
            int option;
            while (true) {
                try {
                    option = sc.nextInt();
                    break;
                } catch (Exception InputMismatchException) {
                    sc.nextLine();
                    System.out.print("Enter an valid option: ");
                }
            }
            switch (option) {
                case 1: {
                    registration();
                    break;
                }
                case 2: {
                    login();
                    break;
                }
                case 3: {
                    adminLogin();
                    break;
                }
                case 4: {
                    changePassword();
                    break;
                }
                case 0: {
                    break;
                }
                default: {
                    System.out.println("Invalid option.");
                }
            }
            if(option == 0){
                System.out.println("Program ended successfully.");
                break;
            }
        }
    }
    public static boolean validUserId(String userId) throws IOException{
        BufferedReader fileReader = new BufferedReader(new FileReader("LogDetails.txt"));
        String line;
        String fileUserId;
        boolean match = false;
        while((line = fileReader.readLine()) != null){
            String[] word = line.split("\\|");
            fileUserId = word[0];
            if(userId.equals(fileUserId)){
                match = true;
            }
        }
        fileReader.close();
        if(match){
            System.out.println("Sorry user id already taken!!");
        }
        return !match && !Character.isWhitespace(userId.charAt(0)) && !Character.isWhitespace(userId.charAt(userId.length() - 1));
    }
    public static boolean validPassword(String password) throws IOException {
        boolean[] validPassChoice = passwordConstrains();
        //System.out.println(""+validPassChoice[0] + validPassChoice[1] + validPassChoice[2] + validPassChoice[3] + validPassChoice[4]);
        boolean isValid = true;
        if(validPassChoice[0] && password.length() < 8){
            System.out.println("Password must contain 8 characters in length");
            isValid = false;
        }
        String upperCaseChars = "(.*[A-Z].*)";
        if(validPassChoice[1] && !password.matches(upperCaseChars)){
            System.out.println("Password must have one uppercase character");
            isValid = false;
        }
        String lowerCaseChars = "(.*[a-z].*)";
        if(validPassChoice[2] && !password.matches(lowerCaseChars)){
            System.out.println("Password must have one lowercase character");
            isValid = false;
        }
        String numbers = "(.*\\d.*)";
        if(validPassChoice[3] && !password.matches(numbers)){
            System.out.println("Password must have one digit");
            isValid = false;
        }
        String specialChars = "(.*[@,$#%].*)";
        if(validPassChoice[4] && !password.matches(specialChars)){
            System.out.println("Password must have one special character among [@,$#%]");
            isValid = false;
        }
        if(Character.isWhitespace(password.charAt(0)) || Character.isWhitespace(password.charAt(password.length() - 1))){
            System.out.println("Please don't leave unwanted space before and after password");
            isValid = false;
        }
        return isValid;
    }
    public static void registration() throws Exception {
        System.out.print("Enter your new user id: ");
        sc.nextLine();
        String userId = sc.nextLine();
        while (true){
            boolean isValid = validUserId(userId);
            if(!isValid){
                System.out.print("Enter valid userid: ");
                userId = sc.nextLine();
            }
            else{
                break;
            }
        }
        System.out.print("Enter your new password: ");
        String password = sc.nextLine();
        while (true){
            if(!validPassword(password)){
                System.out.print("Enter valid password: ");
                password = sc.nextLine();
            }
            else{
                break;
            }
        }
        writeToFile(userId, password);
        System.out.println("Registered successfully");
    }
    public static void createFile(String fileName){
        File file = new File(fileName);
        try {
            file.createNewFile();
        } catch (IOException e){
            throw new RuntimeException(e);
        }
    }
    public static void writeToFile(String userId, String password) throws Exception {
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter("LogDetailsAES.txt", true));
        //String encryptedString = encrypt(password);
        fileWriter.write(userId + "|" + encrypt(password) + "\n");
        fileWriter.close();
    }
    public static boolean scanFromFile(String loginUserId, String loginPassword) throws Exception {
        BufferedReader fileReader = new BufferedReader(new FileReader("LogDetailsAES.txt"));
        String line, fileUserid, filePassword;
        boolean match = false;
        while((line = fileReader.readLine()) != null){
            String[] word = line.split("\\|");
            fileUserid = word[0];
            filePassword = word[1];
            if(loginUserId.equals(fileUserid) && loginPassword.equals(decrypt(filePassword))){
                match = true;
                break;
            }
        }
        fileReader.close();
        return match;
    }
    public static String[] login() throws Exception {
        sc.nextLine();
        System.out.print("Enter your user id: ");
        String loginUserId = sc.nextLine();
        System.out.print("Enter your password: ");
        String loginPassword = sc.nextLine();
        if(scanFromFile(loginUserId, loginPassword)){
            System.out.println("Logged in successfully...");
            //String encodedLoginPassword = Base64.getEncoder().encodeToString(loginPassword.getBytes());
            String encryptedLoginPassword = encrypt(loginPassword);
            return new String[] {loginUserId, encryptedLoginPassword};
        }
        else{
            System.out.println("Invalid user id or password");
            return null;
        }
    }
    public static void adminLogin() throws IOException {
        String adminUserId, adminPassword;
        System.out.print("Enter admin user id: ");
        sc.nextLine();
        adminUserId = sc.nextLine();
        System.out.print("Enter admin password: ");
        adminPassword = sc.nextLine();
        if(adminUserId.equals("admin") && adminPassword.equals("admin@123")){
            System.out.println("Logged in as admin");
            System.out.println();
            boolean tempCount = true;
            while(tempCount){
                System.out.println("1: Password must contain 8 characters in length");
                System.out.println("2: Password must have one uppercase character");
                System.out.println("3: Password must have one lowercase character");
                System.out.println("4: Password must have one digit");
                System.out.println("5: Password must have one special character among [@,#%$]");
                System.out.print("Enter options need to applied(eg: 1, 2, 3): ");
                String passwordConstrain = sc.nextLine();
                String[] passwordConstrainArr = passwordConstrain.split(",");
                for(int i=0; i<passwordConstrainArr.length; i++){
                    for(int j=i+1; j<passwordConstrainArr.length; j++){
                        if(Objects.equals(passwordConstrainArr[i], passwordConstrainArr[j])){
                            System.out.println("Invalid options");
                            System.out.println("Please enter valid options");
                            tempCount = true;
                            break;
                        }
                        else{
                            tempCount = false;
                        }
                    }
                }
                if(!tempCount){
                    createFile("passwordConstrain.txt");
                    BufferedWriter fileWriter = new BufferedWriter(new FileWriter("passwordConstrain.txt"));
                    fileWriter.write(passwordConstrain);
                    fileWriter.close();
                    System.out.println("Password constrains applied");
                }
            }
        }
        else{
            System.out.println("Access denied");
            System.out.println("Invalid user id or password");
        }
    }
    public static void changePassword() throws Exception {
        String[] userIdAndPassword = login();
        String newPassword;
        if(userIdAndPassword != null){
            System.out.print("Enter you new password: ");
            newPassword = sc.nextLine();
            while(true){
                if(!validPassword(newPassword)){
                    System.out.print("Enter valid password: ");
                    newPassword = sc.nextLine();
                }
                else{
                    System.out.println("New password updated successfully");
                    break;
                }
            }
            String oldUserIdPassword = userIdAndPassword[0] + "|" + userIdAndPassword[1];
            String newEncryptedPassword = encrypt(newPassword);
            String newUserIdPassword = userIdAndPassword[0] + "|" + newEncryptedPassword;
            passwordUpdater(oldUserIdPassword, newUserIdPassword);
        }
    }
    public static void passwordUpdater(String oldUserIdPassword, String newUserIdPassword) throws IOException {
        Scanner sc = new Scanner(new File("LogDetailsAES.txt"));
        StringBuilder buffer = new StringBuilder();
        while(sc.hasNextLine()){
            buffer.append(sc.nextLine()).append(System.lineSeparator());
        }
        String fileContents = buffer.toString();
        sc.close();
        fileContents = fileContents.replace(oldUserIdPassword, newUserIdPassword);
        FileWriter writer = new FileWriter("LogDetailsAES.txt");
        writer.append(fileContents);
        writer.flush();
        writer.close();
    }
    public static boolean[] passwordConstrains() throws IOException {
        boolean passwordCount = false, upperCase = false, lowerCase = false, digit = false, specialCharacters = false;
        BufferedReader fileReader = new BufferedReader(new FileReader("passwordConstrain.txt"));
        String line;
        String[] passwordConstrainArr = new String[0];
        while((line = fileReader.readLine()) != null){
            passwordConstrainArr = line.split(",");
        }
        for(String s : passwordConstrainArr){
            switch (s){
                case "1": {
                    passwordCount = true;
                }
                case "2": {
                    upperCase = true;
                }
                case "3": {
                    lowerCase = true;
                }
                case "4": {
                    digit = true;
                }
                case "5": {
                    specialCharacters = true;
                }
            }
        }
        fileReader.close();
        return new boolean[] {passwordCount, upperCase, lowerCase, digit, specialCharacters};
    }
    public static String encrypt(String strToEncrypt) {
        try {
            // Create default byte array
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Create SecretKeyFactory object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivSpec);
            // Return encrypted string
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        }
        catch (Exception e) {
            System.out.println("Error while encrypting: " + e);
        }
        return null;
    }
    // This method use to decrypt to string
    public static String decrypt(String strToDecrypt) {
        try {

            // Default byte array
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            // Create IvParameterSpec object and assign with
            // constructor
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Create SecretKeyFactory Object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            // Return decrypted string
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e);
        }
        return null;
    }
}