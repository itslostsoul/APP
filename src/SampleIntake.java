import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Locale;

/** Reads a suspicious file once, fingerprints it and decides which sandbox runtime should detonate it. */
public final class SampleIntake {

    /** Which container image / launch command a sample is routed to. */
    enum Runtime {
        NATIVE("amas-base", "Linux binary"),
        SHELL("amas-base", "Shell script"),
        PYTHON("amas-python", "Python script"),
        NODE("amas-node", "JavaScript");

        final String image;
        final String label;

        Runtime(String image, String label) {
            this.image = image;
            this.label = label;
        }
    }

    /** Everything we learn about a sample before it is executed. */
    record SampleInfo(Path path, String name, long size, String sha256, String typeLabel,
                      Runtime runtime, boolean supported, String unsupportedReason) {

        String shortHash() { return sha256.substring(0, 8); }
    }

    private SampleIntake() {}

    /** Fingerprints and classifies the file. Throws IOException when it cannot be read. */
    public static SampleInfo inspect(String filePath) throws IOException {
        Path path = Paths.get(filePath).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            throw new IOException("Not a readable file: " + path);
        }

        byte[] head = new byte[64];
        int headLen = 0;
        long size = 0;
        MessageDigest digest = newSha256();

        try (InputStream in = Files.newInputStream(path)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (headLen < head.length) {
                    int take = Math.min(n, head.length - headLen);
                    System.arraycopy(buf, 0, head, headLen, take);
                    headLen += take;
                }
                digest.update(buf, 0, n);
                size += n;
            }
        }

        String name = path.getFileName().toString();
        String ext = extension(name);
        String hash = toHex(digest.digest());

        // Windows PE ("MZ"): the sandbox is Linux-only, so executing it would just crash.
        if (headLen >= 2 && head[0] == 'M' && head[1] == 'Z') {
            return new SampleInfo(path, name, size, hash, "Windows executable (PE)", Runtime.NATIVE, false,
                    "Windows executables can't run in the Linux sandbox. Analyze a Linux binary or script instead.");
        }

        if (headLen >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
            return new SampleInfo(path, name, size, hash, "Linux executable (ELF)", Runtime.NATIVE, true, null);
        }

        String firstLine = "";
        if (headLen >= 2 && head[0] == '#' && head[1] == '!') {
            firstLine = new String(head, 0, headLen, StandardCharsets.ISO_8859_1).split("\n", 2)[0].toLowerCase(Locale.ROOT);
        }

        if (ext.equals("py") || firstLine.contains("python")) {
            return new SampleInfo(path, name, size, hash, Runtime.PYTHON.label, Runtime.PYTHON, true, null);
        }
        if (ext.equals("js") || ext.equals("mjs") || firstLine.contains("node")) {
            return new SampleInfo(path, name, size, hash, Runtime.NODE.label, Runtime.NODE, true, null);
        }
        if (ext.equals("sh") || firstLine.contains("sh")) {
            return new SampleInfo(path, name, size, hash, Runtime.SHELL.label, Runtime.SHELL, true, null);
        }
        return new SampleInfo(path, name, size, hash, "Unknown file type", Runtime.NATIVE, true, null);
    }

    /** SHA-256 only; kept for callers that don't need the full profile. Returns null on failure. */
    public static String generateFileHash(String filePath) {
        try {
            return inspect(filePath).sha256();
        } catch (IOException e) {
            System.err.println("Hashing error: " + e.getMessage());
            return null;
        }
    }

    static String humanSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format(Locale.ROOT, "%.1f KB", kb);
        double mb = kb / 1024.0;
        if (mb < 1024) return String.format(Locale.ROOT, "%.1f MB", mb);
        return String.format(Locale.ROOT, "%.2f GB", mb / 1024.0);
    }

    private static String extension(String name) {
        int i = name.lastIndexOf('.');
        return i > 0 ? name.substring(i + 1).toLowerCase(Locale.ROOT) : "";
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        return sb.toString();
    }
}
