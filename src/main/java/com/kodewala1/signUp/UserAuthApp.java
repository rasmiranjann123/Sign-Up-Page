package com.kodewala1.signUp;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserAuthApp {
	
	private static final String url="jdbc:mysql://localhost:3306/jdbc_demo";
	
	private static final String DB_USER ="root";
	
	private static final String DB_PASSWORD = "Tutun@22n";
	
	private static final Scanner sc = new Scanner(System.in);
	
	 // 1. Establish database connection
	
	public static Connection getConnection() throws SQLException {
		
		return DriverManager.getConnection(url, DB_USER, DB_PASSWORD);
	}
	
	// 2. signUp
	
	public static void signup() {
		
		try {
			System.out.println("Enter Your name: ");
			String name =sc.nextLine().trim();
			
			System.out.print("Enter email: ");
            String email = sc.nextLine().trim();

            System.out.print("Enter password (minimum 8 characters): ");
            String password = sc.nextLine();
            
            if(name.isEmpty() || email.isEmpty() || password.length()<8) {
            	System.out.println("Invalid input.");
                return;
            }
            
            String passwordHash=hashPassword(password);
            
            String sql="INSERT INTO user (name,email,password) VALUES  (?,?,?)";
            
            try(Connection connection=getConnection();
            		PreparedStatement statement=connection.prepareStatement(sql)){
            	
            	statement.setString(1, name);
            	statement.setString(2, email);
            	statement.setString(3, passwordHash);
            	
            	int rows=statement.executeUpdate();
            	
            	if(rows>0) {
            		System.out.println("Signup successful!");
            	}
            }
		}
		
		catch (SQLException e) {
			
			if(e.getSQLState()!=null && e.getSQLState().startsWith("23")) {
				System.out.println("Email already exists.");
			}else {
				System.out.println("Database error: " + e.getMessage());
			}
		}
		
		
		catch (Exception e) {
			System.out.println("Error while signing up.");
		}
	}
	
	
	// 3. Login
	
	public static void login() {
		
		try {
			
			
			System.out.print("Enter email: ");
            String email = sc.nextLine().trim();

            System.out.print("Enter password: ");
            String password = sc.nextLine();
            
            
            String sql="SELECT name, password FROM user WHERE email = ?";
            
            try(Connection connection=getConnection();
            		PreparedStatement statement=connection.prepareStatement(sql)){
            	
            	statement.setString(1, email);
            	
            	try(ResultSet rs=statement.executeQuery()){
            		
            		if(rs.next()) {
            			String storedHash =rs.getString("password");
            			
            			if (verifyPassword(password, storedHash)) {
                            System.out.println("Login successful!");
                            System.out.println(
                                    "Welcome, " + rs.getString("name"));
                        } else {
                            System.out.println(
                                    "Invalid email or password.");
                        }
            		}
            		
            		else {
                        System.out.println(
                                "Invalid email or password.");
                    }
            	}
            }
            
            
		}
		
		catch (Exception e) {
			System.out.println("Login failed: " + e.getMessage());
			
		}
	}
	
	
	
	private static String hashPassword(String password)
            throws Exception {

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, 120000, 256);

        byte[] hash;

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            hash = factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }

        return Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

	

	private static boolean verifyPassword(
            String password, String storedValue) throws Exception {

        String[] parts = storedValue.split(":");

        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] expectedHash = Base64.getDecoder().decode(parts[1]);

        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, 120000, 256);

        byte[] actualHash;

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            actualHash = factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }

        return MessageDigest.isEqual(expectedHash, actualHash);
    }
	
	
	public static void main(String[] args) {

        while (true) {
            System.out.println("\n===== USER AUTHENTICATION =====");
            System.out.println("1. Signup");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");

            String choice = sc.nextLine();

            switch (choice) {
                case "1":
                    signup();
                    break;

                case "2":
                    login();
                    break;

                case "3":
                    System.out.println("Application closed.");
                    sc.close();
                    return;

                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

}
