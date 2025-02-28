const std = @import("std");

pub fn build(b: *std.Build) void {
    // Définir les drapeaux Rust
    const rust_flags = "-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt";

    // Cible principale (release) équivalent à 'make' ou 'make release'
    const release_step = b.step("release", "Build release version");
    const release_cmd = b.addSystemCommand(&[_][]const u8{
        "cargo", "+nightly", "build", "-Zbuild-std", "--release",
    });
    release_cmd.setEnvironmentVariable("RUSTFLAGS", rust_flags);
    release_step.dependOn(&release_cmd.step);

    // Cible pour construire le serveur
    const server_step = b.step("server", "Build server version");
    const server_step_linux = b.step("server-linux", "Build server version for Linux");
    const server_step_windows = b.step("server-windows", "Build server version for Windows");

    const server_cmd = build_server(b, false);
    server_cmd.setEnvironmentVariable("RUSTFLAGS", rust_flags);
    server_step.dependOn(&server_cmd.step);

    const server_cmd_linux = build_server(b, true);
    server_cmd_linux.setEnvironmentVariable("RUSTFLAGS", rust_flags);
    server_step_linux.dependOn(&server_cmd_linux.step);

    const server_cmd_windows = build_server(b, false);
    server_cmd_windows.setEnvironmentVariable("RUSTFLAGS", rust_flags);
    server_step_windows.dependOn(&server_cmd_windows.step);

    // Cible pour construire le TUI
    const tui_step = b.step("tui", "Build TUI version");
    const tui_cmd = b.addSystemCommand(&[_][]const u8{
        "cargo", "+nightly", "build",      "-Zbuild-std", "--release",
        "--bin", "skap-tui", "--features", "tui",
    });
    tui_cmd.setEnvironmentVariable("RUSTFLAGS", rust_flags);
    tui_step.dependOn(&tui_cmd.step);

    // Cible pour exécuter le serveur
    const run_server_step = b.step("run-server", "Build and run server");
    const run_server_cmd = b.addSystemCommand(&[_][]const u8{
        "./target/release/skap-server",
    });
    run_server_cmd.step.dependOn(@constCast(server_step));
    run_server_step.dependOn(&run_server_cmd.step);

    // Cible pour exécuter le TUI
    const run_tui_step = b.step("run-tui", "Build and run TUI");
    run_tui_step.dependOn(tui_step);
    const run_tui_cmd = b.addSystemCommand(&[_][]const u8{
        "./target/release/skap-tui",
    });
    run_tui_step.dependOn(&run_tui_cmd.step);

    // Cible pour exécuter uniquement le TUI (sans construction)
    const only_run_tui_step = b.step("only-run-tui", "Run TUI without building");
    const only_run_tui_cmd = b.addSystemCommand(&[_][]const u8{
        "./target/release/skap-tui",
    });
    only_run_tui_step.dependOn(&only_run_tui_cmd.step);

    // Cible pour exécuter l'exécutable principal
    const run_step = b.step("run", "Run the main binary");
    const run_cmd = b.addSystemCommand(&[_][]const u8{
        "./target/release/skap",
    });
    run_step.dependOn(&run_cmd.step);

    // Cible pour nettoyer le projet
    const clean_step = b.step("clean", "Clean the project");
    const clean_cmd = b.addSystemCommand(&[_][]const u8{
        "cargo", "clean",
    });
    clean_step.dependOn(&clean_cmd.step);

    // Cible pour construire l'image Docker
    const docker_build_step = b.step("docker-build", "Build Docker image");
    const docker_build_cmd = b.addSystemCommand(&[_][]const u8{
        "docker-compose", "build",
    });
    docker_build_cmd.setEnvironmentVariable("DOCKER_BUILDKIT", "1");
    docker_build_cmd.setEnvironmentVariable("COMPOSE_DOCKER_CLI_BUILD", "1");
    docker_build_step.dependOn(&docker_build_cmd.step);

    // Cible pour exécuter les services Docker
    const docker_run_step = b.step("docker-run", "Run Docker services");
    const docker_run_cmd = b.addSystemCommand(&[_][]const u8{
        "docker-compose", "up", "-d",
    });
    docker_run_step.dependOn(&docker_run_cmd.step);

    // Cible pour arrêter les services Docker
    const docker_stop_step = b.step("docker-stop", "Stop Docker services");
    const docker_stop_cmd = b.addSystemCommand(&[_][]const u8{
        "docker-compose", "down",
    });
    docker_stop_step.dependOn(&docker_stop_cmd.step);

    // Cible pour afficher les logs des services Docker
    const docker_logs_step = b.step("docker-logs", "Show Docker logs");
    const docker_logs_cmd = b.addSystemCommand(&[_][]const u8{
        "docker-compose", "logs", "-f",
    });
    docker_logs_step.dependOn(&docker_logs_cmd.step);

    // Définir la cible par défaut
    b.default_step.dependOn(release_step);
}

fn build_server(b: *std.Build, linux: bool) *std.Build.Step.Run {
    var server_cmd: *std.Build.Step.Run = undefined;
    if (linux) {
        server_cmd = b.addSystemCommand(&[_][]const u8{
            "cargo",                    "+nightly",    "build",      "-Zbuild-std", "--release",
            "--bin",                    "skap-server", "--features", "server",      "--target",
            "x86_64-unknown-linux-gnu",
        });
    } else {
        server_cmd = b.addSystemCommand(&[_][]const u8{ "cargo", "+nightly", "build", "-Zbuild-std", "--release", "--bin", "skap-server", "--features", "server" });
    }
    return server_cmd;
}
