import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

import javax.crypto.Cipher;

import com.itextpdf.text.Document;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.opencsv.CSVWriter;

public class Main {
    static Connection c = null;
    static Statement statement = null;
    static Scanner sc = new Scanner(System.in);
    static PreparedStatement preparedStatement = null;
    public static void main(String[] args) throws Exception {
        databaseConnection();
        createTable();
        keyPairProducing();
        while(true) {
            System.out.println(" ");
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
                    login(true);
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
                statement.close();
                c.close();
                System.out.println("Program ended successfully.");
                break;
            }
        }
    }

    public static void databaseConnection() {
        try {
            Class.forName("org.postgresql.Driver");
            c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/postgres", "postgres", "2002");
            System.out.println("Opened database successfully");
            statement = c.createStatement();
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
            System.exit(0);
        }
    }

    public static boolean[] passwordConstrains() throws SQLException {
        boolean passwordCount, upperCase, lowerCase, digit, specialCharacters;
        ResultSet rs = statement.executeQuery("SELECT * FROM PASSWORDCONSTRAINS WHERE SNO=1");
        rs.next();
        passwordCount = rs.getBoolean("CHARLENGTH");
        upperCase = rs.getBoolean("UPPERCASE");
        lowerCase = rs.getBoolean("LOWERCASE");
        digit = rs.getBoolean("DIGIT");
        specialCharacters = rs.getBoolean("SPECIALCHARACTERS");
        return new boolean[] {passwordCount, upperCase, lowerCase, digit, specialCharacters};
    }


    public static boolean validPassword(String password) throws SQLException, NoSuchAlgorithmException, IOException {
        boolean[] validPassChoice = passwordConstrains();
        boolean isValid = true;
        int pwndCount = 0;
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
        if(password.length() == 0 || Character.isWhitespace(password.charAt(0)) || Character.isWhitespace(password.charAt(password.length() - 1))){
            System.out.println("Please don't give empty password \nPlease don't leave unwanted space before and after password");
            isValid = false;
        }
        if(isValid){
            pwndCount = checkHIBP(password);
        }
        if(pwndCount > 0){
            System.out.printf("Your password has been pwned %s times\n", pwndCount);
            isValid = false;
        }
        return isValid;
    }

    public static boolean validUserId(String userId) throws Exception{
        boolean match = false;
        ResultSet rs = null;
        String userIdInDB;
        try {   
            rs = statement.executeQuery("SELECT * FROM LOGDETAILS WHERE USERID = '" + userId + "';");       //////////1234
            if(rs.next()){
            userIdInDB = rs.getString("USERID");
            if(userIdInDB.equals(userId)){
                    match = true;
                    System.out.println("User Id already taken!!!");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        rs.close();
        return userId.length()!=0 && !match && !Character.isWhitespace(userId.charAt(0)) && !Character.isWhitespace(userId.charAt(userId.length() - 1));
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
        writeToDataBase(userId, encrypt(password));
        System.out.println("Registered successfully");
    }
    public static void keyPairProducing() throws NoSuchAlgorithmException, SQLException{
        ResultSet rs = statement.executeQuery("SELECT publickey, privatekey FROM KEYS");
        rs.next();
        if(rs.getString("publickey").equals("Na") || rs.getString("privatekey").equals("Na")){
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keypair = keyGen.genKeyPair();
            PrivateKey privateKey = keypair.getPrivate();
            PublicKey publicKey = keypair.getPublic();
            byte[] publicKeyByte = publicKey.getEncoded();
            byte[] privateKeyByte = privateKey.getEncoded();
            statement.executeUpdate("update keys set publickey=" + "'" + Base64.getEncoder().encodeToString(publicKeyByte) + "'" + " where sno=1;");
            statement.executeUpdate("update keys set privatekey=" + "'" + Base64.getEncoder().encodeToString(privateKeyByte) + "'" + " where sno=1;");
            System.out.println("public.key created");
            System.out.println("private.key created");
        }
    }
    public static PrivateKey getPrivateKey() throws GeneralSecurityException, SQLException {
        ResultSet rs = statement.executeQuery("SELECT publickey, privatekey FROM KEYS");
        rs.next();
        String encodedPrivateKey = rs.getString("privatekey");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey));
        return keyFactory.generatePrivate(privateKeySpec);
    }
    public static PublicKey getPublicKey() throws GeneralSecurityException, SQLException {
        ResultSet rs = statement.executeQuery("SELECT publickey, privatekey FROM KEYS");
        rs.next();
        String encodedPublicKey = rs.getString("publickey");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey));
        return keyFactory.generatePublic(publicKeySpec);
    }
    private static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    private static byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }
    public static String encrypt(String message) throws Exception{
        PublicKey publicKey = getPublicKey();
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }
    public static String decrypt(String encryptedMessage) throws Exception{
        PrivateKey privateKey = getPrivateKey();
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }
    public static String login(boolean changePassword) throws Exception {
        sc.nextLine();
        boolean match;
        String choice; // For account account deletion
        String loginOption = " "; // For personal details changes and account deletion
        System.out.print("Enter your user id: ");
        String loginUserId = sc.nextLine();
        System.out.print("Enter your password: ");
        String loginPassword = sc.nextLine();
        if(loginVerification(loginUserId, loginPassword)){
            System.out.println("Logged in successfully...");
            match = true;
            System.out.println(" ");
            while (!loginOption.equals("0") && changePassword){
                System.out.println("1: Change personal details");
                System.out.println("2: Export personal details");
                System.out.println("3: Delete account");
                System.out.println("0: Previous option");
                System.out.print("=> ");
                //while (true) {
                loginOption = sc.nextLine();
                switch (loginOption) {
                    case "1": {
                        changePersonalDetails(loginUserId);
                        break;
                    }
                    case "2": {
                        System.out.print("Which format you like to export: \n1: PDF\n2: CSV\n3: Text\n0: Previous options\n=> ");
                        boolean formatLoop = true;
                        while(formatLoop){
                            String formatOption = sc.nextLine();
                            switch(formatOption){
                                case "1": {
                                    exportToPdf(loginUserId);
                                    formatLoop = false;
                                    break;
                                }
                                case "2": {
                                    exportToCSV(loginUserId);
                                    formatLoop = false;
                                    break;
                                }
                                case "3": {
                                    exportToTextFile(loginUserId);
                                    formatLoop = false;
                                    break;
                                }
                                case "0": {
                                    formatLoop = false;
                                    break;
                                }
                                default: {
                                    System.out.print("Please Enter a valid oprion: ");
                                }
                            }
                        }
                        break;
                    }
                    case "3": {
                        System.out.print("Do you want to delete your account(y/n): ");
                        while (true) {
                            choice = sc.nextLine();
                            if (choice.length() == 1 && (choice.equals("y") || choice.equals("Y"))) {
                                statement.executeUpdate("DELETE FROM LOGDETAILS WHERE USERID=" + "'" + loginUserId + "';");
                                System.out.println("Account successfully deleted!!!");
                                loginOption = "0";
                                break;
                            } else if (choice.length() == 1 && (choice.equals("n") || choice.equals("N"))) {
                                System.out.println("Thanks for staying with us");
                                break;
                            } else {
                                System.out.print("Please enter a vaild choice: ");
                                //sc.nextLine();
                            }
                        }
                    }
                    case "0": {
                        break;
                    }
                    default: {
                        System.out.println("Invalid option");
                    }
                }
            }
        }
        else{
            System.out.println("Invalid user id or password");
            match = false;
        }
        if(match){
            return loginUserId; 
        }
        else{
            return null;
        }
    }

    public static void adminLogin() throws Exception {
        String adminUserId, adminPassword;
        System.out.print("Enter admin user id: ");
        sc.nextLine();
        adminUserId = sc.nextLine();
        System.out.print("Enter admin password: ");
        adminPassword = sc.nextLine();
        if(adminUserId.equals("admin") && adminPassword.equals("admin@123")) {
            System.out.println("Logged in as admin");
            System.out.println();
            System.out.println("Select operation to perform: ");
            System.out.println("1: Apply password constrains");
            System.out.println("0: Previous option");
            System.out.print("=> ");
            int option;
            while (true) {
                try {
                    option = sc.nextInt();
                    sc.nextLine();
                    if(option == 1 || option == 0){
                        break;
                    }
                    else{
                    System.out.print("Enter an valid option: ");
                    }
                } catch (Exception InputMismatchException) {
                    sc.nextLine();
                    System.out.print("Enter an valid option: ");
                }
            }
            switch (option){
                case 1: {
                    passwordConstrainsToDB();
                    break;
                }
                case 0: {
                    break;
                }
                default: {
                    System.out.print("Enter a valid option: ");
                    sc.nextLine();
                }
            }
        }
        else{
            System.out.println("Access denied");
            System.out.println("Invalid user id or password");
        }
    }
    public static void passwordConstrainsToDB() throws SQLException {
        boolean tempCount = true;
        String[] passwordConstrainArr = new String[4];
        while(tempCount) {
            System.out.println("1: Password must contain 8 characters in length");
            System.out.println("2: Password must have one uppercase character");
            System.out.println("3: Password must have one lowercase character");
            System.out.println("4: Password must have one digit");
            System.out.println("5: Password must have one special character among [@,#%$]");
            System.out.print("Enter options need to applied(eg: 1,2,3): ");
            String passwordConstrain = sc.nextLine();
            passwordConstrainArr = passwordConstrain.split(",");
            int i, j;
            if(passwordConstrain.length()!=1){
                for(i=0; i<passwordConstrainArr.length; i++){
                    for(j=i+1; j<passwordConstrainArr.length; j++){
                        if(Objects.equals(passwordConstrainArr[i], passwordConstrainArr[j])){
                            System.out.println("\nInvalid options");
                            System.out.println("Please enter valid options");
                            tempCount = true;
                            break;
                        }
                        else{
                            tempCount = false;
                        }
                    }
                    if(tempCount){
                        break;
                    }
                }
            }
            else{
                tempCount = false;
            }
        }
        preparedStatement = c.prepareStatement("UPDATE PASSWORDCONSTRAINS SET CHARLENGTH=?, UPPERCASE=?, LOWERCASE=?, DIGIT=?, SPECIALCHARACTERS=? WHERE SNO=1;");
        for(int i=1; i<=5; i++){
            boolean match = false;
            for(int j=0; j<passwordConstrainArr.length; j++){
                if(Integer.parseInt(passwordConstrainArr[j]) == i){
                    match = true;
                    break;
                }
            }
            preparedStatement.setBoolean(i, match);
        }
        preparedStatement.executeUpdate();
          
        System.out.println("Password constrains applied");
    }

    public static void changePassword() throws Exception {
        boolean changePassword = false;
        String userId = login(changePassword);
        String newPassword;
        if(userId != null){
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
            String newEncryptedPassword = encrypt(newPassword);
            String changePasswordQuery = "UPDATE LOGDETAILS set PASSWORD=" + " '"+newEncryptedPassword + "'" + " where USERID=" + " '" + userId + "'" + ";";
            statement.executeUpdate(changePasswordQuery);
            System.out.println("Password changed successfully....");
        }
    }
    public static String validData(){
        while(true){
            String data = sc.nextLine();
            if(data.length()!=0 && !Character.isWhitespace(data.charAt(0)) && !Character.isWhitespace(data.charAt(data.length() - 1))){
                return data;
            }
            else{
                System.out.print("Enter a vaild data: ");
            }
        }
    }
    public static void writeToDataBase(String userId, String encyptedPassword) throws SQLException{     //////////1234
        preparedStatement = c.prepareStatement("INSERT INTO LOGDETAILS (USERID, PASSWORD, NAME, DATEOFBIRTH, CONTACTNUMBER, EMAILID, CITY) VALUES (?, ?, ?, ?, ?, ?, ?);");
        
        preparedStatement.setString(1, userId);
        preparedStatement.setString(2, encyptedPassword);
        
        System.out.println("Please fill your personal details.");
        System.out.print("Enter you name: ");
        preparedStatement.setString(3, validData());
        
        System.out.print("Enter your date of birth: ");
        preparedStatement.setString(4, validData());
        
        System.out.print("Enter your contact number: ");
        preparedStatement.setString(5, validData());
        
        System.out.print("Enter your email id: ");
        preparedStatement.setString(6, validData());
        
        System.out.print("Enter your city: ");
        preparedStatement.setString(7, validData());
        preparedStatement.executeUpdate();
    }

    

    public static boolean loginVerification(String loginUserId, String loginPassword) throws Exception{  //////////1234
        boolean match = false;
        ResultSet rs = null;
        String dataBaseUserId, dataBasePassword;
        try {
            rs = statement.executeQuery("SELECT * FROM LOGDETAILS WHERE USERID='" + loginUserId + "';");
            if(rs.next()){
                dataBaseUserId = rs.getString("USERID");
                dataBasePassword = rs.getString("PASSWORD");
                if(dataBaseUserId.equals(loginUserId) && decrypt(dataBasePassword).equals(loginPassword)){
                    match = true;
                }
            }
            rs.close();
        } catch (Exception e) {
            e.printStackTrace();
        } 
        return match;
    }

    public static void createTable() throws SQLException{
        String logDetailsQuery = "CREATE TABLE IF NOT EXISTS LOGDETAILS (USERID TEXT PRIMARY KEY, PASSWORD TEXT);";
        statement.executeUpdate(logDetailsQuery);
    }

    public static void changePersonalDetails(String loginUserId) throws SQLException{   //////////1234
        preparedStatement = c.prepareStatement("UPDATE LOGDETAILS SET NAME = ?, DATEOFBIRTH = ?, CONTACTNUMBER = ?, EMAILID = ?, CITY = ? WHERE USERID=?;");

        System.out.println("Please fill your personal details.");
        System.out.print("Enter you name: ");
        preparedStatement.setString(1, validData());
        
        System.out.print("Enter your date of birth: ");
        preparedStatement.setString(2, validData());
        
        System.out.print("Enter your contact number: ");
        preparedStatement.setString(3, validData());
        
        System.out.print("Enter your email id: ");
        preparedStatement.setString(4, validData());
        
        System.out.print("Enter your city: ");
        preparedStatement.setString(5, validData());

        preparedStatement.setString(6, loginUserId);

        preparedStatement.executeUpdate();

        System.out.println("Personal details successfully updated");
    }

    public static void exportToPdf(String userId) throws SQLException{
        ResultSet rs = statement.executeQuery("SELECT * FROM LOGDETAILS WHERE USERID=" + "'" + userId + "';");
        rs.next();
        Document document = new Document();
        String pdfName = userId + ".pdf";
        try {
            PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(pdfName));
            PdfPTable table = new PdfPTable(2);

            table.addCell("Name");
            table.addCell(rs.getString("NAME"));
            
            table.addCell("Date of birth");
            table.addCell(rs.getString("DATEOFBIRTH"));

            table.addCell("Conatact number");
            table.addCell(rs.getString("CONTACTNUMBER"));

            table.addCell("Email id");
            table.addCell(rs.getString("EMAILID"));

            table.addCell("City");
            table.addCell(rs.getString("CITY"));

            document.open();
            document.add(table);  
            document.close();
            writer.close();    
            System.out.println("PDF successfully generated");  
           } catch (Exception e) {
               e.printStackTrace();
           }
    }

    public static void exportToCSV(String userId) throws SQLException{
        ResultSet rs = statement.executeQuery("SELECT * FROM LOGDETAILS WHERE USERID=" + "'" + userId + "';");
        if(rs.next()){
            String csvFileName = userId + ".csv";
            File file = new File(csvFileName);
            try {
                FileWriter outputFile = new FileWriter(file);
                CSVWriter writer = new CSVWriter(outputFile);
                String[] header = {"Name", "Date of birth", "Contact number", "Email id", "City"};
                writer.writeNext(header);
                String[] data = {rs.getString("NAME"),rs.getString("DATEOFBIRTH"), rs.getString("CONTACTNUMBER"), rs.getString("EMAILID"), rs.getString("CITY")};
                writer.writeNext(data);
                writer.close();
                System.out.println("CSV successfully generated");  
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void exportToTextFile(String userId) throws SQLException{
        ResultSet rs = statement.executeQuery("SELECT * FROM LOGDETAILS WHERE USERID=" + "'" + userId + "';");
        if(rs.next()){
            try {
                String textFileName = userId + ".txt";
                String paragraphFormat = "Name : " + rs.getString("NAME") + "\n" + "Date of birth : " + rs.getString("DATEOFBIRTH") + "\n" + "Contact number : "  + rs.getString("CONTACTNUMBER") + "\n" + "Email Id : " + rs.getString("EMAILID") + "\n" + "City : " + rs.getString("CITY");
                BufferedWriter fileWriter = new BufferedWriter(new FileWriter(textFileName));
                fileWriter.write(paragraphFormat);
                fileWriter.close();
                System.out.println("CSV successfully generated");
            } catch (Exception e) {
                e.getStackTrace();
            }
        }
    }

    public static int checkHIBP(String password) throws IOException, NoSuchAlgorithmException{

        MessageDigest messageDigest = null;
        messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] bytesOfDigestedPassword = messageDigest.digest(password.getBytes("utf-8"));


        ////    bytes to Hex
        StringBuffer hexStringBuffer = new StringBuffer();
        for(int i = 0; i < bytesOfDigestedPassword.length; i++){
            char[] hexDigits = new char[2];

            hexDigits[0] = Character.forDigit((bytesOfDigestedPassword[i] >> 4) & 0xF, 16);
			hexDigits[1] = Character.forDigit((bytesOfDigestedPassword[i] & 0xF), 16);
			String byteToHex = new String(hexDigits);
			hexStringBuffer.append(byteToHex);
        }
        String sha1password = hexStringBuffer.toString().toUpperCase();
        
        //// first 5 hex characters

        String head = sha1password.substring(0, 5);
		String tail = sha1password.substring(5);
        

        URL url = new URL("https://api.pwnedpasswords.com/range/" + head);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");

        ////    Reading from server

        BufferedReader res = new BufferedReader(new InputStreamReader(con.getInputStream()));


        //// Checking the occurrance of password 

        String line = null;
		int count = 0;

		while ((line = res.readLine()) != null) {
			if (line.split(":")[0].equals(tail))
				count = Integer.parseInt(line.split(":")[1]);
		}
        return count;
    }
}