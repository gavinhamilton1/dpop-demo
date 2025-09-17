// scripts/copy-assets.js
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import { mkdirSync, cpSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const targetVendor = resolve(__dirname, "..", "public", "vendor", "tasks-vision");
const targetWasm = resolve(targetVendor, "wasm");

// Ensure directories exist
mkdirSync(targetVendor, { recursive: true });
mkdirSync(targetWasm, { recursive: true });

// Copy the ESM bundle
cpSync(
  resolve(__dirname, "..", "node_modules", "@mediapipe", "tasks-vision", "vision_bundle.mjs"),
  resolve(targetVendor, "vision_bundle.mjs"),
  { recursive: true }
);

// Copy all WASM/JS worker files
cpSync(
  resolve(__dirname, "..", "node_modules", "@mediapipe", "tasks-vision", "wasm"),
  targetWasm,
  { recursive: true }
);

console.log("✓ MediaPipe assets copied to public/vendor/tasks-vision");
