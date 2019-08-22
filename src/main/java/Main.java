import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

public class Main {

    public static void main(String[] args) throws Throwable {
        new Main().start();
    }

    public void start() throws Throwable {
        byte[] document = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

        TimestampResult result = makeTimestamp(document);
        result.validate();
        System.out.println(result.getTsr().getTimeStampToken().getTimeStampInfo().getGenTime());

    }

    class TimestampResult {
        private TimeStampRequest tsq;
        private TimeStampResponse tsr;

        public TimeStampRequest getTsq() {
            return tsq;
        }

        public void setTsq(TimeStampRequest tsq) {
            this.tsq = tsq;
        }

        public TimeStampResponse getTsr() {
            return tsr;
        }

        public void setTsr(TimeStampResponse tsr) {
            this.tsr = tsr;
        }

        public void validate() throws TSPException {
            tsr.validate(tsq);
        }
    }

    public TimestampResult makeTimestamp(byte[] data) throws Throwable {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);

            TimeStampRequestGenerator tsReqGen = new TimeStampRequestGenerator();
            tsReqGen.setCertReq(false); // Будет ли сертификат приложен к ответу
            TimeStampRequest tsq = tsReqGen.generate(CMSAlgorithm.SHA256, digest);

            TimeStampResponse tsr = getServiceTimestamp(tsq.getEncoded());

            TimestampResult result = new TimestampResult();
            result.setTsq(tsq);
            result.setTsr(tsr);
            return result;
        } catch (Throwable t) {
            throw new Exception("Невозможно получить timestamp");
        }
    }


    private TimeStampResponse getServiceTimestamp(byte[] tsqData) throws Throwable {

        InputStream input = null;
        HttpURLConnection connection = null;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byte[] result;

        URL url = new URL("http://tsp.pki.gov.kz");
        connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.connect();
        OutputStream connectionOutputStream = connection.getOutputStream();
        connectionOutputStream.write(tsqData);

        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            return null;
        }

        input = connection.getInputStream();

        int count;
        byte[] data = new byte[4096];
        while ((count = input.read(data)) != -1) {

            byteArrayOutputStream.write(data, 0, count);
        }
        connection.disconnect();
        result = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();
        return new TimeStampResponse(result);
    }

    public static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}