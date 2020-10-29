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
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;

public class Client {
    private static final String IP_ADDRESS = "localhost";
    private static final int PORT = 8080;

    private static boolean isConnected_;
    private static Socket socket_;

    public Client(){
        isConnected_ = false;
    }

    public static void connectToServer() throws IOException {
        socket_ = new Socket(IP_ADDRESS,  PORT);
        isConnected_ = true;
    }

    public static void closeConnection() {
        if (!isConnected_) {
            return;
        }
        try {
            socket_.close();
        } catch (IOException e) {
            /* cannot happen */
        }
        isConnected_ = false;
    }

    public static void main(String[] args) throws IOException {
        try {
            connectToServer();
            Scanner sc = new Scanner(System.in);

            // DataInputStream and DataOutputStream created
            DataInputStream in = new DataInputStream(socket_.getInputStream());
            DataOutputStream out = new DataOutputStream(socket_.getOutputStream());

            String inputParameters = in.readUTF();
            int N = Integer.parseInt(inputParameters.split(" ")[0]);
            int g = Integer.parseInt(inputParameters.split(" ")[1]);
            int k = Integer.parseInt(inputParameters.split(" ")[2]);
            new SRP6(N, g, k);

            System.out.println("Sign up or sign in ? (1 or 2)");
            if (sc.nextLine().equals("1")) {
                out.writeUTF(SRP6.signUp());

                String response = in.readUTF();

                if (response.equals("Such user exists .")) {
                    System.out.println("Try again . " + response);
                } else {
                    System.out.println("Registration was succeeded .");
                }
            } else {
                Random random = new Random();
                int a = random.nextInt();
                String authorization = SRP6.signIn(a);

                out.writeUTF(authorization);

                String response = in.readUTF();

                if (response.equals("Such user does not exist .")) {
                    System.out.println("Try again . " + response);
                } else {
                    //
                    String salt = response.split(" ")[0];
                    int B = Integer.parseInt(response.split(" ")[1]);

                    int u = SRP6.canculateArbitraryParameterToEncode(authorization.split(" ")[1], B);

                    int S = SRP6.canculateSessionKeyForClient(a, B, salt, u);

                    int K = SRP6.canculateEncryptionKey(S);
                    System.out.println("\nEncryption key K = " + K);

                    /* First level of verification */
                    int M = SRP6.doFirstLevelOfVerification(authorization.split(" ")[0], salt,
                            authorization.split(" ")[1], B, K);
                    System.out.println("\nFirst level of verification M = " + M);

                    out.writeUTF(String.valueOf(M));

                    /* Second level of verification */
                    String answer = in.readUTF();
                    if (!answer.equals("Connection was failed .")) {
                        int R = SRP6.doSecondLevelOfVerification(authorization.split(" ")[1], M, K);
                        System.out.println("\nSecond level of verification R = " + R);
                        if (Integer.parseInt(answer) == R) {
                            System.out.println("\nConnection installed .");
                        } else {
                            System.out.println("\nConnection was failed .");
                        }
                    }
                }
            }
            in.close();
            out.close();
        } catch (IOException | NumberFormatException e) {
            e.printStackTrace();
        }
        closeConnection();
    }
}