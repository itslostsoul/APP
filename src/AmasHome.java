import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Locates the project folder so reports and the Docker build context resolve no matter where AMAS is launched from. */
final class AmasHome {
    private static Path cached;

    private AmasHome() {}

    static synchronized Path root() {
        if (cached != null) return cached;
        String env = System.getenv("AMAS_HOME");
        if (env != null && !env.isBlank() && Files.isDirectory(Paths.get(env))) {
            return cached = Paths.get(env).toAbsolutePath().normalize();
        }
        Path[] starts = { Paths.get("").toAbsolutePath(), codeLocation() };
        for (Path start : starts) {
            Path p = start;
            for (int i = 0; p != null && i < 4; i++, p = p.getParent()) {
                if (Files.isRegularFile(p.resolve("docker").resolve("Dockerfile"))) {
                    return cached = p.normalize();
                }
            }
        }
        return cached = Paths.get("").toAbsolutePath();
    }

    private static Path codeLocation() {
        try {
            Path loc = Paths.get(AmasHome.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return Files.isDirectory(loc) ? loc : loc.getParent();
        } catch (Exception e) {
            return Paths.get("").toAbsolutePath();
        }
    }

    static Path reports() {
        String env = System.getenv("AMAS_REPORTS");
        Path dir = (env != null && !env.isBlank()) ? Paths.get(env) : root().resolve("reports");
        try { Files.createDirectories(dir); } catch (Exception ignored) {}
        return dir;
    }

    static Path dockerDir() { return root().resolve("docker"); }
    static Path dashboardScript() { return root().resolve("dashboard").resolve("app.py"); }
}
