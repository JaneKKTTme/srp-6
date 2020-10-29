/*
 * Author: Jane Khomenko
 *
 * Github: JaneKKTTme
 *
 * Email: tyryry221@gmail.com
 *
 * Date: 22.10.2020
 */

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;
import java.util.Scanner;

public class SRP6 {
    /* Session parameters */
    private static int generatorOnModuleSophieGermainPrime;
    private static int sophieGermainPrime;
    private static int parameterMultiplier;

    private static final int MAX_VALUE = 120;
    private static final int MIN_VALUE = 2;

    public SRP6() {
        sophieGermainPrime = generateSophieGermainPrime();
        generatorOnModuleSophieGermainPrime = calculateGeneratorOnModuleSophieGermainPrime();
        parameterMultiplier = 3;
    }

    public SRP6(int _sophieGermainPrime, int _generatorOnModuleSophieGermainPrime, int _parameterMultiplier) {
        sophieGermainPrime = _sophieGermainPrime;
        generatorOnModuleSophieGermainPrime = _generatorOnModuleSophieGermainPrime;
        parameterMultiplier = _parameterMultiplier;
    }

    protected static int canculateArbitraryParameterToEncode(String A, int B) {
        return generateSecretKeyWithHashFunction(Integer.parseInt(A), B);
    }

    protected static int canculateEncryptionKey(int S) {
        return generateSecretKeyWithHashFunction(S, 0);
    }

    private static Integer calculateGeneratorOnModuleSophieGermainPrime() {
        ArrayList<Integer> generatorsOnModuleSophieGermainPrime = new ArrayList<>();

        ArrayList<Integer> antiderivativeRootsOnModule = pickUpAntiderivativeRootsOnModule();

        for (int supposedGenerator = MIN_VALUE; supposedGenerator < sophieGermainPrime; supposedGenerator++) {
            Collection<Integer> copyOfAntiderivativeRootsOnModule = (Collection<Integer>) antiderivativeRootsOnModule.clone();
            Collection<Integer> suitableDegrees = new ArrayList<>();
            for (int degree = 1; degree < sophieGermainPrime; degree++) {
                if (!suitableDegrees.contains((int) Math.pow(supposedGenerator, degree) % sophieGermainPrime))
                    suitableDegrees.add((int) Math.pow(supposedGenerator, degree) % sophieGermainPrime);
            }
            suitableDegrees.removeAll(copyOfAntiderivativeRootsOnModule);
            if (suitableDegrees.isEmpty()) {
                generatorsOnModuleSophieGermainPrime.add(supposedGenerator);
            }
        }

        return generatorsOnModuleSophieGermainPrime.get(0);
    }

    protected static int canculateSecretKey(String input) {
        return generateSecretKeyWithHashFunction(input);
    }

    protected static int canculateSessionKeyForClient(int a, int B, String salt, int u) {
        int x = canculateSecretKey(enterPassword() + salt);
        return (int) Math.pow(B - sophieGermainPrime * Math.pow(generatorOnModuleSophieGermainPrime, x), a + u * x);
    }

    protected static int canculateSessionKeyForServer(String A, String v, int u, int b) {
        return (int) Math.pow(Integer.parseInt(A) * Math.pow(Integer.parseInt(v), u), b);
    }

    private static void checkConditionOfSophieGermainPrime(ArrayList<Integer> simpleNumbers) {
        for (int i = 0; i < simpleNumbers.size(); i++) {
            if (!simpleNumbers.contains(simpleNumbers.get(i) * 2 + 1)) {
                simpleNumbers.remove(simpleNumbers.get(i));
                i--;
            }
        }
    }

    /*
     * createSalt() - generate random set of numbers (salt) to safeguard  passwords in storage
     */
    private static long createSalt() {
        String symbols = "0123456789";
        int size = 10;
        StringBuilder salt = new StringBuilder();

        Random random = new Random();
        for (int i = 0; i < size; i++) {
            salt.append(symbols.charAt(random.nextInt(symbols.length() - 1)));
        }

        return Long.parseLong(salt.toString());
    }

    protected static int doFirstLevelOfVerification(String username, String salt, String A, int B,
                                                    int K) {
        return generateSecretKeyWithHashFunction(
                generateSecretKeyWithHashFunction(sophieGermainPrime, 0)
                        ^ generateSecretKeyWithHashFunction(generatorOnModuleSophieGermainPrime, 0),
                SRP6.generateSecretKeyWithHashFunction(username),
                Long.parseLong(salt),
                Integer.parseInt(A),
                B,
                K);
    }

    protected static int doSecondLevelOfVerification(String A, int M, int K) {
        return generateSecretKeyWithHashFunction(Integer.parseInt(A), M, K);
    }

    /*
     * doSieveOfEratosthenes() - accomplish sieve of Eratosthenes algorithm
     */
    private static ArrayList<Integer> doSieveOfEratosthenes() {
        ArrayList<Integer> simpleNumbers = new ArrayList<>();

        for (int i = MIN_VALUE; i <= MAX_VALUE; i++) {
            simpleNumbers.add(i);
        }

        //  Delete all numbers that are not simple but composite
        for (int i = 0; i <= simpleNumbers.size() + 2; i++) {
            for (int j = i + 1; j < simpleNumbers.size(); j++) {
                if (simpleNumbers.get(j) % simpleNumbers.get(i) == 0) {
                    simpleNumbers.remove(j);
                }
            }
        }

        return simpleNumbers;
    }

    protected static String enterPassword() {
        System.out.println("Password : ");
        Scanner sc = new Scanner(System.in);

        return sc.nextLine();
    }

    private static String enterUsername() {
        System.out.println("Username : ");
        Scanner sc = new Scanner(System.in);

        return sc.nextLine();
    }

    private static int generateSecretKeyWithHashFunction(String input) {
        int hash = 0;
        for (int i = 0; i < input.length(); i++) {
            hash += input.charAt(i) * Math.pow(31, i);
        }

        return hash % 13;
    }

    private static int generateSecretKeyWithHashFunction(int A, int B) {
        int hash = A + B;
        String inputToString = Long.toString(hash);
        hash = 0;

        for (int i = 0; i < inputToString.length(); i++) {
            hash += inputToString.charAt(i) * Math.pow(31,i);
        }

        return hash % 13;
    }

    private static int generateSecretKeyWithHashFunction(int A, int M, int K) {
        long hash = A  + M + K;
        String inputToString = Long.toString(hash);
        hash = 0;

        for (int i = 0; i < inputToString.length(); i++) {
            hash += inputToString.charAt(i) * Math.pow(11, i);
        }

        return (int) hash % 45625;
    }

    private static int generateSecretKeyWithHashFunction(int HN_xor_Hg, int hashOfUsername, long salt, int A, int B,
                                                         int K) {
        long hash = HN_xor_Hg + hashOfUsername + salt + A  + B + K;
        String inputToString = Long.toString(hash);
        hash = 0;

        for(int i = 0; i < inputToString.length(); i++) {
            hash += inputToString.charAt(i) * Math.pow(11, i);
        }

        return (int) hash % 133;
    }

    private static Integer generateSophieGermainPrime() {
        ArrayList<Integer> sophieGermainPrimes = doSieveOfEratosthenes();

        checkConditionOfSophieGermainPrime(sophieGermainPrimes);
        sophieGermainPrimes.remove(0);

        Random random = new Random(System.currentTimeMillis());
        return sophieGermainPrimes.get(random.nextInt(sophieGermainPrimes.size()));
    }

    public static int getGeneratorOnModuleSophieGermainPrime() {
        return generatorOnModuleSophieGermainPrime;
    }

    public static int getSophieGermainPrime() {
        return sophieGermainPrime;
    }

    public static int getParameterMultiplier() {
        return parameterMultiplier;
    }

    public static String signIn(int randomNumber) {
        /* Calculate secret A using random numbers*/
        int A = (int) Math.pow(generatorOnModuleSophieGermainPrime, randomNumber) % sophieGermainPrime;

        return enterUsername() + " " + A;
    }
    
    public static String signUp() {
        long salt = createSalt();
        String password = enterPassword();

        int secretKey = canculateSecretKey(password + salt);

        // Verificate password : (generatorOnModuleSophieGermainPrime ^ secretKey) % sophieGermainPrime
        int passwordVerifier = (int) Math.pow(generatorOnModuleSophieGermainPrime, secretKey) % sophieGermainPrime;

        return enterUsername() + " " + salt + " " + passwordVerifier;
    }

    private static ArrayList<Integer> pickUpAntiderivativeRootsOnModule() {
        ArrayList<Integer> antiderivativeRoot = new ArrayList<>();

        /*
         * Check the condition of existence an antiderivative root : g ^ i[k] mod p != 1 , where :
         * 1) g - sought antiderivative root on module p;
         * 2) p - number for which is searched g;
         * 3) i[k] - one of p divisors
         */
        for (int degree = 1; degree < sophieGermainPrime; degree++) {
            int amountOfExecutedCondition = 0;
            for (int i = MIN_VALUE; i < sophieGermainPrime; i++) {
                if (Math.pow(degree, i) % sophieGermainPrime != 1) {
                    amountOfExecutedCondition += 1;
                }
            }
            if (amountOfExecutedCondition != sophieGermainPrime - 2) {
                antiderivativeRoot.add(degree);
            }
        }

        return antiderivativeRoot;
    }
}
