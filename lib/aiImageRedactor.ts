import { createWorker } from "tesseract.js";

function isSensitiveWord(wordText: string): boolean {
  const cleaned = wordText.trim();
  if (cleaned.length < 3) return false;

  // Count how many digits (0-9) are in this word
  const digitCount = (cleaned.match(/\d/g) || []).length;

  // 1. Catch any 3+ digit block (catches 4-digit ID chunks, DOBs, PIN codes, Phone numbers)
  if (digitCount >= 3) return true;

  // 2. Catch Emails or common ID keywords
  if (cleaned.includes("@")) return true;
  if (/^(sk_|ghp_|AIza|DOB|MALE|FEMALE|VID)/i.test(cleaned)) return true;

  return false;
}

export async function scanAndBlurImagePII(imageFile: File): Promise<{
  redactedBlob: Blob;
  redactedCount: number;
}> {
  try {
    console.log("👁️ Starting OCR scan on:", imageFile.name);

    // 1. Create Tesseract Worker & explicitly enable 'blocks' output for v5+
    const worker = await createWorker("eng");
    const result = await worker.recognize(imageFile, {}, { blocks: true });
    await worker.terminate();

    // 2. Extract all words from nested blocks -> paragraphs -> lines -> words
    const allWords: { text: string; bbox: { x0: number; y0: number; x1: number; y1: number } }[] = [];
    const data: any = result.data;

    if (data.words && data.words.length > 0) {
      allWords.push(...data.words);
    } else if (data.blocks) {
      for (const block of data.blocks) {
        for (const para of block.paragraphs || []) {
          for (const line of para.lines || []) {
            for (const word of line.words || []) {
              allWords.push(word);
            }
          }
        }
      }
    }

    console.log(`📝 OCR detected ${allWords.length} words:`, allWords.map((w) => w.text));

    // 3. Filter sensitive words & get their Bounding Boxes
    const sensitiveBoxes = allWords
      .filter((w) => isSensitiveWord(w.text))
      .map((w) => w.bbox);

    console.log(`🛡️ Found ${sensitiveBoxes.length} sensitive boxes to redact!`);

    if (sensitiveBoxes.length === 0) {
      return { redactedBlob: imageFile, redactedCount: 0 };
    }

    // 4. Draw Image on Canvas & Censor Sensitive Boxes
    const imgBitmap = await createImageBitmap(imageFile);
    const canvas = document.createElement("canvas");
    canvas.width = imgBitmap.width;
    canvas.height = imgBitmap.height;

    const ctx = canvas.getContext("2d");
    if (!ctx) return { redactedBlob: imageFile, redactedCount: 0 };

    ctx.drawImage(imgBitmap, 0, 0);

    for (const bbox of sensitiveBoxes) {
      const pad = 6;
      const x = Math.max(0, bbox.x0 - pad);
      const y = Math.max(0, bbox.y0 - pad);
      const w = bbox.x1 - bbox.x0 + pad * 2;
      const h = bbox.y1 - bbox.y0 + pad * 2;

      // Solid Dark Censor Box
      ctx.fillStyle = "#020617";
      ctx.fillRect(x, y, w, h);

      // Neon Emerald AI Border
      ctx.strokeStyle = "#10b981";
      ctx.lineWidth = Math.max(2, Math.round(canvas.width / 300));
      ctx.strokeRect(x, y, w, h);
    }

    // 5. Convert Canvas back to Blob
    const redactedBlob = await new Promise<Blob>((resolve) => {
      canvas.toBlob((b) => resolve(b || imageFile), "image/png", 0.95);
    });

    return { redactedBlob, redactedCount: sensitiveBoxes.length };
  } catch (err) {
    console.error("❌ OCR Image Shield Error:", err);
    return { redactedBlob: imageFile, redactedCount: 0 };
  }
}