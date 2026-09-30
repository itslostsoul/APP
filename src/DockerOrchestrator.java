import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Detonates a sample inside a locked-down, disposable Docker container and streams what happens.
 *
 * Isolation applied to every run: no network, 512 MB RAM (swap off), 1 CPU, 128 processes, all Linux capabilities
 * dropped, no-new-privileges, read-only root filesystem, a small non-executable-by-default scratch /tmp,
 * an unprivileged user, and the sample bind-mounted read-only.
 */
public final class DockerOrchestrator {

    /** Hard ceiling for one detonation. Overridable with AMAS_TIMEOUT (seconds). */
    static final long TIMEOUT_SECONDS = envLong("AMAS_TIMEOUT", 60);

    private static final String STRACE =
            "strace -f -qq -s 96 -e trace=%file,%network,execve ";

    private static volatile String activeContainer;

    private DockerOrchestrator() {}

    /** Stops the running detonation, if any. Called when the app window closes so nothing keeps running unattended. */
    static void killActive() {
        String name = activeContainer;
        if (name != null) quietly(List.of("docker", "kill", name));
    }

    // ------------------------------------------------------------------ public API

    /** Returns the Docker server version, or null when the daemon can't be reached. */
    static String dockerVersion() {
        try {
            ExecResult r = exec(List.of("docker", "version", "--format", "{{.Server.Version}}"), 12);
            String v = r.output.trim();
            return r.exit == 0 && !v.isEmpty() ? v : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Runs one full analysis and always returns a report-backed result (failures are reported as failures, never as verdicts). */
    static Analysis run(SampleIntake.SampleInfo sample, Consumer<LogEvent> out) {
        Analysis result;
        try {
            result = detonate(sample, out);
        } catch (Exception e) {
            emit(out, LogEvent.Kind.ERROR, "Analysis failed: " + e.getMessage());
            result = BehaviorAnalyzer.failed(sample, e.getMessage());
        }
        save(result, out);
        return result;
    }

    /** Feeds a saved strace log through the analyzer without Docker. Handy for testing and demos. */
    static Analysis replay(SampleIntake.SampleInfo sample, Path traceFile, int exitCode, Consumer<LogEvent> out) throws IOException {
        emit(out, LogEvent.Kind.SYSTEM, "Replaying " + traceFile.getFileName() + " (no container is started)");
        BehaviorAnalyzer analyzer = new BehaviorAnalyzer();
        for (String line : Files.readAllLines(traceFile, StandardCharsets.UTF_8)) {
            LogEvent e = analyzer.feed(line);
            if (e != null) out.accept(e);
        }
        Analysis a = analyzer.finish(sample, "replay", exitCode, false, 0, TIMEOUT_SECONDS);
        finishLog(a, out);
        save(a, out);
        return a;
    }

    // ------------------------------------------------------------------ detonation

    private static Analysis detonate(SampleIntake.SampleInfo sample, Consumer<LogEvent> out) throws Exception {
        emit(out, LogEvent.Kind.SYSTEM, "Checking Docker...");
        String version = dockerVersion();
        if (version == null) {
            String msg = "Docker isn't running. Start Docker Desktop (or the docker service), then analyze again.";
            emit(out, LogEvent.Kind.ERROR, msg);
            return BehaviorAnalyzer.failed(sample, msg);
        }
        emit(out, LogEvent.Kind.SUCCESS, "Docker " + version + " is ready");

        String image = sample.runtime().image;
        String buildError = ensureImage(image, out);
        if (buildError != null) {
            emit(out, LogEvent.Kind.ERROR, buildError);
            return BehaviorAnalyzer.failed(sample, buildError);
        }

        String hostPath = sample.path().toString();
        if (hostPath.contains(",") || hostPath.contains("\"")) {
            String msg = "The file path contains a comma or quote, which Docker can't mount safely. Move the sample to a simpler path.";
            emit(out, LogEvent.Kind.ERROR, msg);
            return BehaviorAnalyzer.failed(sample, msg);
        }

        String containerName = "amas-" + sample.shortHash() + "-" + Long.toString(System.currentTimeMillis(), 36);
        List<String> cmd = new ArrayList<>(List.of(
                "docker", "run",
                "--name", containerName,
                "--rm",
                "--network", "none",
                "--memory", "512m", "--memory-swap", "512m",
                "--cpus", "1.0",
                "--pids-limit", "128",
                "--ulimit", "nofile=256:256",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--read-only",
                "--tmpfs", "/tmp:rw,exec,nosuid,size=64m,mode=1777",
                "--user", "10001:10001",
                "--hostname", "sandbox",
                "--label", "amas.sample=" + sample.shortHash(),
                "--mount", "type=bind,source=" + hostPath + ",target=/sandbox/sample,readonly",
                image,
                "sh", "-c", launchCommand(sample.runtime())));

        emit(out, LogEvent.Kind.SYSTEM, "Detonating " + sample.name() + " in " + image
                + " (no network, 512 MB, 1 CPU, read-only, no capabilities)");

        BehaviorAnalyzer analyzer = new BehaviorAnalyzer();
        long started = System.nanoTime();

        activeContainer = containerName;
        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        final String[] firstLine = {null};

        Thread reader = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (firstLine[0] == null && !line.isBlank()) firstLine[0] = line;
                    LogEvent e = analyzer.feed(line);
                    if (e != null) out.accept(e);
                }
            } catch (IOException ignored) {
                // The stream closes when the process is killed on timeout. That's expected.
            }
        }, "amas-reader");
        reader.setDaemon(true);
        reader.start();

        boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        boolean timedOut = !finished;
        int exit;
        if (timedOut) {
            emit(out, LogEvent.Kind.WARN, "Time limit of " + TIMEOUT_SECONDS + " s reached. Stopping the container.");
            process.destroyForcibly();
            quietly(List.of("docker", "kill", containerName));
            quietly(List.of("docker", "rm", "-f", containerName));
            exit = -1;
        } else {
            exit = process.exitValue();
        }
        reader.join(3000);
        activeContainer = null;
        long durationMs = (System.nanoTime() - started) / 1_000_000;

        // Exit 125 (or a "docker:" first line) means Docker itself failed, not the sample.
        if (!timedOut && (exit == 125 || (firstLine[0] != null && firstLine[0].startsWith("docker:")))) {
            String msg = "Docker couldn't start the sandbox: " + (firstLine[0] != null ? firstLine[0] : "exit code 125");
            emit(out, LogEvent.Kind.ERROR, msg);
            return BehaviorAnalyzer.failed(sample, msg);
        }

        Analysis a = analyzer.finish(sample, image, exit, timedOut, durationMs, TIMEOUT_SECONDS);
        finishLog(a, out);
        return a;
    }

    private static String launchCommand(SampleIntake.Runtime rt) {
        return switch (rt) {
            case PYTHON -> "cp /sandbox/sample /tmp/payload.py && " + STRACE + "python /tmp/payload.py";
            case NODE -> "cp /sandbox/sample /tmp/payload.js && " + STRACE + "node /tmp/payload.js";
            case SHELL -> "cp /sandbox/sample /tmp/payload.sh && " + STRACE + "sh /tmp/payload.sh";
            case NATIVE -> "cp /sandbox/sample /tmp/payload && chmod +x /tmp/payload && " + STRACE + "/tmp/payload";
        };
    }

    /** Builds the runtime image from docker/Dockerfile the first time it's needed. Returns an error message or null. */
    private static String ensureImage(String image, Consumer<LogEvent> out) throws Exception {
        if (exec(List.of("docker", "image", "inspect", image), 15).exit == 0) return null;

        String target = image.substring("amas-".length());
        Path dir = AmasHome.dockerDir();
        if (!Files.isRegularFile(dir.resolve("Dockerfile"))) {
            return "Missing " + dir.resolve("Dockerfile") + ". Run AMAS from the project folder or set AMAS_HOME.";
        }
        emit(out, LogEvent.Kind.SYSTEM, "First run: building the " + image + " image (this can take a minute)...");
        Process p = new ProcessBuilder("docker", "build", "--target", target, "-t", image, dir.toString())
                .redirectErrorStream(true).start();
        List<String> tail = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (tail.size() >= 12) tail.remove(0);
                tail.add(line);
            }
        }
        if (!p.waitFor(300, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return "Building " + image + " timed out after 5 minutes. Check your internet connection and try again.";
        }
        if (p.exitValue() != 0) {
            return "Building " + image + " failed:\n" + String.join("\n", tail);
        }
        emit(out, LogEvent.Kind.SUCCESS, image + " is built");
        return null;
    }

    // ------------------------------------------------------------------ helpers

    private static void finishLog(Analysis a, Consumer<LogEvent> out) {
        if (a.timedOut) {
            emit(out, LogEvent.Kind.WARN, "Detonation stopped at the time limit");
        } else {
            emit(out, LogEvent.Kind.SUCCESS, "Detonation finished (exit code " + a.exitCode + ") and the container was destroyed");
        }
        emit(out, a.score >= 15 ? LogEvent.Kind.WARN : LogEvent.Kind.SUCCESS,
                "Verdict: " + a.level.label + " (risk " + a.score + "/100)");
    }

    private static void save(Analysis a, Consumer<LogEvent> out) {
        try {
            Path p = ReportGenerator.write(a);
            emit(out, LogEvent.Kind.SYSTEM, "Report saved: " + p.getFileName());
        } catch (IOException e) {
            emit(out, LogEvent.Kind.ERROR, "Couldn't write the report: " + e.getMessage());
        }
    }

    private static void emit(Consumer<LogEvent> out, LogEvent.Kind kind, String text) {
        out.accept(LogEvent.of(kind, text));
    }

    private record ExecResult(int exit, String output) {}

    private static ExecResult exec(List<String> cmd, long timeoutSeconds) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        StringBuilder sb = new StringBuilder();
        Thread t = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append('\n');
            } catch (IOException ignored) {}
        });
        t.setDaemon(true);
        t.start();
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return new ExecResult(-1, sb.toString());
        }
        t.join(1000);
        return new ExecResult(p.exitValue(), sb.toString());
    }

    private static void quietly(List<String> cmd) {
        try { exec(cmd, 15); } catch (Exception ignored) {}
    }

    private static long envLong(String name, long fallback) {
        try {
            String v = System.getenv(name);
            return v == null ? fallback : Math.max(5, Long.parseLong(v.trim()));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    static String describe(Analysis a) {
        return a.failed ? "Analysis failed" : String.format(Locale.ROOT, "%s (%d/100)", a.level.label, a.score);
    }
}
