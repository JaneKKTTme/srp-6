/*
 * Author: Jane Khomenko
 *
 * Github: JaneKKTTme
 *
 * Email: tyryry221@gmail.com
 *
 * Date: 22.10.2020
 */

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Random;

public class Server {
    private static ServerSocket serverSocket_;
    private static Socket socket_;
    private static final Integer port_ = 8080;

    public static void closeConnection() {
        try {
            serverSocket_.close();
        } catch (IOException e) { /* cannot happen */ }
    }

    public static void start() {
        try {
            socket_ = serverSocket_.accept();
        } catch (IOException e) { /* cannot happen */ }
    }

    public static void main(String[] args) throws Exception {
        // Server started ...
        serverSocket_ = new ServerSocket(port_);

        // Start new session
        new SRP6();

        ArrayList<User> database = new ArrayList<>();

        while (true) {
            // Server connected ...
            start();

            try {
                // DataInputStream and DataOutputStream created
                DataInputStream in = new DataInputStream(socket_.getInputStream());
                DataOutputStream out = new DataOutputStream(socket_.getOutputStream());

                // Send session parameters to Client
                out.writeUTF(SRP6.getSophieGermainPrime() + " " + SRP6.getGeneratorOnModuleSophieGermainPrime()
                        + " " + SRP6.getParameterMultiplier());

                // Receive  from Client 
                String[] request = (in.readUTF()).split(" ");

                /*
                 Check type of connection : signing up or signing in .
                 If amount of parameters equal to 3 , it is sign up .
                 If amount of parameters equal to 2 , it is sign in .
                 */
                if (request.length == 3) { // register
                    if (database.isEmpty()) {
                        System.out.println("Registration was successed .");
                        database.add(new User(request[0], request[1], request[2]));

                        out.writeUTF("Registration was successed .");
                    } else {
                        for (int i = 0; i < database.size(); i++) {
                            /* Check such user's existence in database */
                            if (database.get(i).getUsername().equals(request[0])) {
                                System.out.println("Such user exists .");
                                out.writeUTF("Such user exists .");
                            } else {
                                System.out.println("Registration was successed .");
                                database.add(new User(request[0], request[1], request[2]));
                                out.writeUTF("Registration was successed .");
                                i++;
                            }
                        }
                    }
                } else if (request.length == 2) { // authorize
                    if (database.isEmpty()) {
                        System.out.println("Such user does not exist .");

                        out.writeUTF("Such user does not exist .");
                    } else {
                        for (int i = 0; i < database.size(); i++) {
                            if (database.get(i).getUsername().equals(request[0])) {
                                /* Generate random one time ephemeral key */
                                Random random = new Random();
                                int b = random.nextInt();
                                int B = SRP6.getParameterMultiplier() * Integer.parseInt(database.get(i).getPasswordVerifier())
                                        + (int) Math.pow(SRP6.getGeneratorOnModuleSophieGermainPrime(), b);
                                out.writeUTF(database.get(i).getSalt() + " " + B);

                                int u = SRP6.canculateArbitraryParameterToEncode(request[1], B);

                                int S = SRP6.canculateSessionKeyForServer(request[1], database.get(i).getPasswordVerifier(), u, b);

                                int K = SRP6.canculateEncryptionKey(S);
                                System.out.println("\nEncryption key K = " + K);

                                /* First level of verification */
                                int M = SRP6.doFirstLevelOfVerification(request[0], database.get(i).getSalt(), request[1], B, K);
                                System.out.println("\nFirst level of verification M = " + M);

                                if (M == Integer.parseInt(in.readUTF())) {
                                    /* Second level of verification */
                                    int R = SRP6.doSecondLevelOfVerification(request[1], M, K);
                                    System.out.println("\nSecond level of verification R = " + R);

                                    out.writeUTF(String.valueOf(R));
                                } else {
                                    System.out.println("\nConnection was failed .");
                                    out.writeUTF("Connection was failed .");
                                }
                            } /*else {
                                out.writeUTF("Such user does not exist .");
                            }*/
                        }
                        out.writeUTF("Such user does not exist .");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            //out.close();
            //in.close();
            //closeConnection();
        }
    }

    // Structure for storing data from Client
    private static class User {
        private final String username;
        private final String salt;
        private final String passwordVerifier;

        public User(String _username, String _salt, String _passwordVerifier) {
            username = _username;
            salt = _salt;
            passwordVerifier = _passwordVerifier;
        }

        public String getUsername() {
            return username;
        }

        public String getSalt() {
            return salt;
        }

        public String getPasswordVerifier() {
            return passwordVerifier;
        }
    }
}