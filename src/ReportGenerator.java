import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Writes report-&lt;id&gt;.json (read by the dashboard) and report-&lt;id&gt;.txt (for humans) into the reports folder. */
public final class ReportGenerator {

    private static final DateTimeFormatter HUMAN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private ReportGenerator() {}

    /** Writes both files and returns the JSON path. */
    static Path write(Analysis a) throws IOException {
        Path dir = AmasHome.reports();
        Path json = dir.resolve("report-" + a.id + ".json");
        Files.writeString(json, Json.write(toMap(a)), StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("report-" + a.id + ".txt"), toText(a), StandardCharsets.UTF_8);
        return json;
    }

    static Map<String, Object> toMap(Analysis a) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", 1);
        root.put("id", a.id);
        root.put("status", a.failed ? "failed" : "completed");
        root.put("created_at", a.createdAt.toString());
        root.put("error", a.error);

        Map<String, Object> sample = new LinkedHashMap<>();
        if (a.sample != null) {
            sample.put("name", a.sample.name());
            sample.put("sha256", a.sample.sha256());
            sample.put("size", a.sample.size());
            sample.put("type", a.sample.typeLabel());
        }
        root.put("sample", sample);

        Map<String, Object> run = new LinkedHashMap<>();
        run.put("image", a.image);
        run.put("exit_code", a.failed ? null : a.exitCode);
        run.put("timed_out", a.timedOut);
        run.put("duration_ms", a.durationMs);
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("network", "none");
        limits.put("memory_mb", 512);
        limits.put("cpus", 1.0);
        limits.put("pids", 128);
        limits.put("timeout_s", a.timeoutSeconds);
        limits.put("capabilities", "dropped (ALL)");
        limits.put("filesystem", "read-only");
        run.put("limits", limits);
        root.put("run", run);

        Map<String, Object> verdict = new LinkedHashMap<>();
        verdict.put("level", a.level.code);
        verdict.put("label", a.level.label);
        verdict.put("score", a.failed ? null : a.score);
        root.put("verdict", verdict);

        List<Object> findings = new ArrayList<>();
        for (Analysis.Finding f : a.findings) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.id());
            m.put("severity", f.severity());
            m.put("title", f.title());
            m.put("detail", f.detail());
            m.put("points", f.points());
            findings.add(m);
        }
        root.put("findings", findings);

        List<Object> events = new ArrayList<>();
        for (Analysis.Event e : a.events) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", e.type());
            m.put("severity", e.severity());
            m.put("label", e.label());
            m.put("detail", e.detail());
            m.put("blocked", e.blocked());
            m.put("pid", e.pid());
            events.add(m);
        }
        root.put("events", events);

        Map<String, Object> iocs = new LinkedHashMap<>();
        iocs.put("network", new ArrayList<>(a.iocNetwork));
        iocs.put("files", new ArrayList<>(a.iocFiles));
        iocs.put("processes", new ArrayList<>(a.iocProcesses));
        root.put("iocs", iocs);

        root.put("output", a.output);
        root.put("notes", a.notes);
        root.put("raw_log", a.rawLog);
        return root;
    }

    static String toText(Analysis a) {
        StringBuilder sb = new StringBuilder();
        String bar = "=".repeat(64);
        sb.append(bar).append('\n');
        sb.append("  AMAS  |  Automated Malware Analysis Sandbox report\n");
        sb.append(bar).append('\n');

        if (a.sample != null) {
            row(sb, "Sample", a.sample.name());
            row(sb, "SHA-256", a.sample.sha256());
            row(sb, "Type", a.sample.typeLabel() + ", " + SampleIntake.humanSize(a.sample.size()));
        }
        row(sb, "Analyzed", HUMAN.format(a.createdAt));

        if (a.failed) {
            sb.append('\n').append("ANALYSIS FAILED (this says nothing about the sample)\n");
            sb.append("  ").append(a.error).append('\n');
            return sb.toString();
        }

        row(sb, "Runtime", a.image);
        row(sb, "Exit code", a.timedOut ? "killed after " + a.timeoutSeconds + " s (timeout)" : String.valueOf(a.exitCode));
        if (a.durationMs > 0) row(sb, "Duration", String.format(Locale.ROOT, "%.1f s", a.durationMs / 1000.0));
        sb.append('\n');
        sb.append("VERDICT  ").append(a.level.label).append("   (risk score ").append(a.score).append("/100)\n");
        sb.append("-".repeat(64)).append('\n');

        if (a.findings.isEmpty()) {
            sb.append("  No findings.\n");
        }
        for (Analysis.Finding f : a.findings) {
            sb.append(String.format(Locale.ROOT, "  [%-8s] %s  (+%d)%n", f.severity(), f.title(), f.points()));
            sb.append("             ").append(f.detail()).append('\n');
        }

        section(sb, "BEHAVIOUR");
        if (a.events.isEmpty()) sb.append("  Nothing observed.\n");
        for (Analysis.Event e : a.events) {
            sb.append(String.format(Locale.ROOT, "  %-11s %s%s%n", e.type(), e.label(), e.blocked() ? "  [blocked]" : ""));
            sb.append("              ").append(e.detail()).append('\n');
        }

        section(sb, "INDICATORS OF COMPROMISE");
        sb.append("  Network   : ").append(a.iocNetwork.isEmpty() ? "none" : String.join(", ", a.iocNetwork)).append('\n');
        sb.append("  Files     : ").append(a.iocFiles.isEmpty() ? "none" : String.join(", ", a.iocFiles)).append('\n');
        sb.append("  Processes : ").append(a.iocProcesses.isEmpty() ? "none" : String.join("; ", a.iocProcesses)).append('\n');

        if (!a.output.isEmpty()) {
            section(sb, "PROGRAM OUTPUT");
            for (String line : a.output) sb.append("  ").append(line).append('\n');
        }
        if (!a.notes.isEmpty()) {
            section(sb, "NOTES");
            for (String n : a.notes) sb.append("  - ").append(n).append('\n');
        }
        sb.append('\n').append("Heuristic triage only. It is not an antivirus verdict.\n");
        return sb.toString();
    }

    private static void row(StringBuilder sb, String key, String value) {
        sb.append(String.format(Locale.ROOT, "  %-10s %s%n", key, value));
    }

    private static void section(StringBuilder sb, String title) {
        sb.append('\n').append(title).append('\n').append("-".repeat(64)).append('\n');
    }
}
