#!/usr/bin/env node
import { runCli } from "./cli/commands.js";

runCli(process.argv.slice(2), { log: console.log, error: console.error }).catch(
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  },
);
