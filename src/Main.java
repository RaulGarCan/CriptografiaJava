import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;

public class Main {
    private static String cifradoActual;
    private static SealedObject objetoSellado;
    public static void main(String[] args) {
        boolean ejecucion = true;
        Scanner userInput = new Scanner(System.in);
        System.out.print("Introduce tu nombre: ");
        String nombre = userInput.nextLine().strip();
        System.out.print("Introduce tu edad: ");
        int edad = Integer.parseInt(userInput.nextLine());
        System.out.print("Introduce tu altura: ");
        double altura = Double.parseDouble(userInput.nextLine());
        Persona p = new Persona(nombre, edad, altura);
        do {
            System.out.println("\n1- Cifrar\n2- Descifrar\n3- Mostrar Datos\n");
            System.out.print("Elige una opción: ");
            String opcion = userInput.nextLine();
            switch (opcion) {
                case "1": // Cifrar
                    System.out.println("\n1- Cifrado DES\n2- Cifrado AES\n");
                    System.out.print("Elige una opción: ");
                    String opcionCifrado = userInput.nextLine().strip();
                    switch (opcionCifrado) {
                        case "1": // Cifrado DES
                            System.out.print("Introduce la clave: ");
                            String claveDES = userInput.nextLine().strip();
                            Cipher cipherDES = crearCifradoDES(claveDES);
                            try {
                                objetoSellado = new SealedObject(p, cipherDES);
                                cifradoActual = "DES";
                            } catch (IOException | IllegalBlockSizeException e) {
                                throw new RuntimeException(e);
                            }
                            break;
                        case "2": // Cifrado AES
                            System.out.print("Introduce la clave: ");
                            String claveAES = userInput.nextLine().strip();
                            objetoSellado = cifrarAES(generarClaveAES(claveAES), p);
                            break;
                        default:
                            System.out.println("Opción no válida");
                            break;
                    }
                    break;
                case "2": // Descifrar
                    if(cifradoActual!=null){
                        System.out.print("Introduce la clave: ");
                        String clave = userInput.nextLine().strip();
                        if(cifradoActual.equalsIgnoreCase("DES")){
                            Cipher cipher = crearDescifradoDES(clave);
                            try {
                                p = (Persona) objetoSellado.getObject(cipher);
                                cifradoActual = null;
                            } catch (IOException | IllegalBlockSizeException | BadPaddingException |
                                     ClassNotFoundException e) {
                                System.out.println("Clave errónea");
                            }
                        } else {
                            p = descifrarAES(generarClaveAES(clave), objetoSellado);
                            cifradoActual = null;
                        }
                    } else {
                        System.out.println("Primero debes cifrar los datos.");
                    }
                    break;
                case "3": // Mostrar Datos
                    if(cifradoActual==null){
                        System.out.println("\nPersona\n"+p+"\n");
                    } else {
                        System.out.println("Debes descifrar primero los datos.");
                    }
                    break;
                default:
                    System.out.println("Cerrando el programa...");
                    ejecucion = false;
                    break;
            }
        } while (ejecucion);
    }

    private static Cipher crearCifradoDES(String clave) {
        try {
            int longitudRestante = 24-clave.length();
            for(int i = 0; i<=longitudRestante; i++){
                clave+=" ";
            }
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            DESKeySpec kspec = new DESKeySpec(clave.getBytes());
            SecretKey ks = skf.generateSecret(kspec);
            Cipher cifrado = Cipher.getInstance("DES");
            cifrado.init(Cipher.ENCRYPT_MODE, ks);
            return cifrado;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    private static Cipher crearDescifradoDES(String clave) {
        try {
            int longitudRestante = 24-clave.length();
            for(int i = 0; i<=longitudRestante; i++){
                clave+=" ";
            }
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            DESKeySpec kspec = new DESKeySpec(clave.getBytes());
            SecretKey ks = skf.generateSecret(kspec);
            Cipher cifrado = Cipher.getInstance("DES");
            cifrado.init(Cipher.DECRYPT_MODE, ks);
            return cifrado;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    private static SecretKey generarClaveAES(String clave){
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(clave.toCharArray(), "salt".getBytes(), 60000, 256);
            SecretKey secretKey = factory.generateSecret(spec);
            return secretKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    private static SealedObject cifrarAES(SecretKey clave, Persona p){
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clave);
            return new SealedObject(p, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException |
                 IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }
    private static Persona descifrarAES(SecretKey clave, SealedObject objetoSellado){
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, clave);
            return (Persona) objetoSellado.getObject(clave);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException |
                 ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}