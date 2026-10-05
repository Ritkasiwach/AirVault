import * as ort from "onnxruntime-web";

// WASM binaries CDN se load karne ke liye taaki Next.js webpack config me lafda na ho
ort.env.wasm.wasmPaths = "https://cdn.jsdelivr.net/npm/onnxruntime-web@1.20.1/dist/";

let session: ort.InferenceSession | null = null;

// 1. Load ONNX Model in Browser (Singleton)
export async function loadSecretScannerModel() {
  if (session) return session;
  try {
    session = await ort.InferenceSession.create("/secret_scanner.onnx", {
      executionProviders: ["wasm"],
    });
    console.log("🧠 Edge-AI ONNX Secret Scanner Loaded!");
    return session;
  } catch (err) {
    console.warn("ONNX Model load failed, using fallback entropy math:", err);
    return null;
  }
}

// 2. Same 4 Features Extraction in TypeScript (Entropy, NormLen, DigitRatio, UpperRatio)
export function extractFeaturesJS(s: string): [number, number, number, number] {
  const len = s.length;
  if (len === 0) return [0, 0, 0, 0];

  const freq: Record<string, number> = {};
  let digits = 0;
  let uppers = 0;

  for (const ch of s) {
    freq[ch] = (freq[ch] || 0) + 1;
    if (ch >= "0" && ch <= "9") digits++;
    if (ch >= "A" && ch <= "Z") uppers++;
  }

  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return [entropy, Math.min(len / 50.0, 2.0), digits / len, uppers / len];
}

// 3. Scan Text File & Mask Secrets using ONNX Inference!
export async function scanAndMaskSecrets(textContent: string): Promise<{
  maskedText: string;
  secretsFound: number;
}> {
  const model = await loadSecretScannerModel();
  let secretsFound = 0;

  // Potential tokens (14+ characters without spaces/quotes) ko test karo
  const tokenRegex = /[A-Za-z0-9_\-\.\/\+]{14,}/g;
  const matches = Array.from(new Set(textContent.match(tokenRegex) || []));

  let maskedText = textContent;

  for (const token of matches) {
    // Ignore pure file paths or URLs
    if (token.startsWith("http") || token.includes("node_modules") || token.includes("localhost")) {
      continue;
    }

    const [entropy, normLen, digitRatio, upperRatio] = extractFeaturesJS(token);
    let isSecret = false;

    if (model) {
      // Run real ONNX Inference in Browser!
      const inputTensor = new ort.Tensor("float32", Float32Array.from([entropy, normLen, digitRatio, upperRatio]), [1, 4]);
      const results = await model.run({ float_input: inputTensor });
      const prediction = Number(results.label.data[0]);
      isSecret = prediction === 1 && entropy > 3.5;
    } else {
      // Fallback if .onnx file wasn't generated yet
      isSecret = entropy > 3.75 && token.length >= 16 && (digitRatio > 0.1 || upperRatio > 0.1);
    }

    if (isSecret) {
      secretsFound++;
      const preview = token.slice(0, 4) + "•••••••••••• [AI-MASKED]";
      maskedText = maskedText.split(token).join(preview);
    }
  }

  return { maskedText, secretsFound };
}