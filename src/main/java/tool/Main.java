package tool;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Created by roderick on 2017/3/17.
 */
public class Main {

    private static Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, ParserConfigurationException, IllegalAccessException, MarshalException, KeyException, InstantiationException, XMLSignatureException, TransformerException, ClassNotFoundException, CertificateException, KeyStoreException, UnrecoverableEntryException, SAXException, URISyntaxException, ZipException {
        //D:\XmlSignEncryptZip\src\test\java\
        System.out.print("source folder : ");
        Scanner scanner = new Scanner(System.in);
        String filefolder = scanner.nextLine();
        File fFolder = new File(filefolder);

        while (!fFolder.exists() || !fFolder.isDirectory()) {
            System.out.print("source folder : ");
            filefolder = scanner.next();
            fFolder = new File(filefolder);
        }

        System.out.print("zip password : ");
        String password = scanner.nextLine();

        while (password.length() == 0) {
            System.out.print("zip password : ");
            password = scanner.nextLine();
        }


        File[] files = new File(filefolder).listFiles();


        XmlCreater xmlCreater = new XmlCreater("");

        Element eai = xmlCreater.createRootElement("eai");
        xmlCreater.createElement(eai, "TransactionId", UUID.randomUUID().toString());
        Element FileList = xmlCreater.createElement(eai, "FileList");

        for (File file : files) {
            if (file.isFile()) {
                Element File = xmlCreater.createElement(FileList, "File");
                xmlCreater.createElement(File, "FileName", file.getName());
                xmlCreater.createElement(File, "Checksum", SHACheckSumGenerator(file));
            }
        }


        File xml = sign(xmlCreater.getDoc(), fFolder.getPath() + "\\");

        String zipFileName = fFolder.getParentFile().getPath() + "\\" + xml.getName().replace("CHECKLIST_", "").replace(".xml", "") + ".zip";
        File zip = new File(zipFileName);
        int i = 1;
        while (zip.exists()) {
            zipFileName = zipFileName.replace(".zip", "(" + Integer.toString(i) + ")");
            zip = new File(zipFileName);
            i++;
        }


        ZipFile zipFile = new ZipFile(zip.getPath());
        ZipParameters zipParameters = new ZipParameters();
        files = new File(filefolder).listFiles();
        ArrayList filesList = new ArrayList();

        for (File file : files) {
            if (file.isFile()) {
                filesList.add(file);
            }
        }

        zipParameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
        zipParameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(Zip4jConstants.ENC_METHOD_AES);
        zipParameters.setAesKeyStrength(Zip4jConstants.AES_STRENGTH_256);
        zipParameters.setPassword(password);

        zipFile.addFiles(filesList, zipParameters);
        xml.delete();
        System.out.println("finish!!");
        System.out.println("zip file : " + zipFileName);
    }

    public static String SHACheckSumGenerator(File file) throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(file);

        byte[] dataBytes = new byte[1024];

        int nread = 0;
        while ((nread = fis.read(dataBytes)) != -1) {
            md.update(dataBytes, 0, nread);
        }
        ;
        byte[] mdbytes = md.digest();

        //convert the byte to hex format method 1
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mdbytes.length; i++) {
            sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public static File sign(Document doc, String targetFolder) throws InstantiationException, IllegalAccessException, ClassNotFoundException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, MarshalException, XMLSignatureException,
            IOException, TransformerException, CertificateException, KeyStoreException, UnrecoverableEntryException, ParserConfigurationException, SAXException, URISyntaxException {
        // Create a DOM XMLSignatureFactory that will be used to
        // generate the enveloped signature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Reference ref = fac.newReference
                ("", fac.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);

        // Create the SignedInfo.
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), Collections.singletonList(ref));

        // Load the KeyStore and get the signing key and certificate.
        String pwd = "pa$$w0rd";
        String alias = "wildfly";
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(Main.class.getResourceAsStream("/wildfly.keystore"), pwd.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(ks.getKey(alias, pwd.toCharArray()), doc.getDocumentElement());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();

        // output the resulting document
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yMMddHHmmssSSS");
        String targetFilePath = targetFolder + "CHECKLIST_" + now.format(dateTimeFormatter) + ".xml";

        File targetFile = new File(targetFilePath);
        while (targetFile.isFile() || targetFile.exists()) {
            targetFilePath = targetFolder + "CHECKLIST_" + now.plus(1, ChronoUnit.MILLIS).format(dateTimeFormatter) + ".xml";
            targetFile = new File(targetFilePath);
        }

        OutputStream os = new FileOutputStream(targetFilePath);
        trans.transform(new DOMSource(doc), new StreamResult(os));
        os.close();
        return targetFile;
    }
}
