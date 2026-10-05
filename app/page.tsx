"use client";

import { useState, useRef, useEffect } from "react";
import {
  Shield,
  Sparkles,
  ArrowRight,
  Send,
  Wifi,
  CheckCircle2,
  Loader2,
  FolderUp,
  FileUp,
  FileText,
  Folder,
  HardDrive,
  Download,
  Eye,
  X,
  Gauge,
  Search,
  Lock,
  QrCode,
  Copy,
  Check,
  Users,
  Trash2,
  Flame,
  Archive,
  ShieldCheck,
} from "lucide-react";
import type Peer from "peerjs";
import type { DataConnection } from "peerjs";
import { scanAndMaskSecrets } from "@/lib/aiSecretScanner";
import { scanAndBlurImagePII } from "@/lib/aiImageRedactor";
import { deriveRoomKey, encryptChunk, decryptChunk } from "@/lib/cryptoEngine";

const ID_PREFIX = "airvault-p2p-";
const CHUNK_SIZE = 64 * 1024; // 64KB per chunk

interface VirtualFileMeta {
  id: string;
  name: string;
  path: string;
  size: number;
  type: string;
  ownerPeerId?: string;
}

const IGNORED_DIRS = ["node_modules", ".git", ".next", "dist", "build", ".vscode"];

// Helper: Web Crypto SHA-256 Hash Generator for File Integrity Verification
async function computeSHA256(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default function Home() {
  const [roomId, setRoomId] = useState("");
  const [joinedRoom, setJoinedRoom] = useState("");
  const [status, setStatus] = useState<"idle" | "waiting" | "connecting" | "connected">("idle");
  const [peerCount, setPeerCount] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");

  // Share & QR Modal States
  const [showQrModal, setShowQrModal] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  // VFS & Drag-Drop States
  const [myFiles, setMyFiles] = useState<VirtualFileMeta[]>([]);
  const [remoteFiles, setRemoteFiles] = useState<VirtualFileMeta[]>([]);
  const [ignoredCount, setIgnoredCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [isDragging, setIsDragging] = useState(false);

  // Edge-AI, Crypto & Burn-After-Reading States
  const [aiShieldEnabled, setAiShieldEnabled] = useState(true);
  const [burnAfterPull, setBurnAfterPull] = useState(false);
  const burnAfterPullRef = useRef(false);
  const [shieldLog, setShieldLog] = useState<string>("");
  const [encryptedChunksCount, setEncryptedChunksCount] = useState(0);

  // Progress, SHA-256 Verification, ZIP & Live Preview States
  const [downloadProgress, setDownloadProgress] = useState<Record<string, number>>({});
  const [verifiedHashes, setVerifiedHashes] = useState<Record<string, string>>({});
  const [isZipping, setIsZipping] = useState(false);
  const [transferSpeed, setTransferSpeed] = useState<string>("0 KB/s");
  const [previewModal, setPreviewModal] = useState<{
    name: string;
    type: "text" | "image" | "video" | "audio" | "pdf";
    content: string;
    sha256?: string;
  } | null>(null);

  // Chat States
  const [msgInput, setMsgInput] = useState("");
  const [messages, setMessages] = useState<{ sender: string; text: string }[]>([]);

  // 🕸️ MULTI-PEER SWARM & VFS REFERENCES
  const peerRef = useRef<Peer | null>(null);
  const connectionsRef = useRef<DataConnection[]>([]);
  const localFileMapRef = useRef<Map<string, File>>(new Map());
  const localMetaListRef = useRef<VirtualFileMeta[]>([]);
  const cryptoKeyRef = useRef<CryptoKey | null>(null);

  // ZIP Collector Reference (when user clicks "Pull All as ZIP")
  const zipCollectorRef = useRef<{
    active: boolean;
    pendingIds: Set<string>;
    files: { name: string; blob: Blob }[];
  }>({ active: false, pendingIds: new Set(), files: [] });

  // Incoming File Chunks Buffer
  const incomingBuffersRef = useRef<
    Map<
      string,
      {
        chunks: ArrayBuffer[];
        receivedBytes: number;
        startTime: number;
        mode: "download" | "preview" | "zip";
        expectedHash?: string;
        meta: VirtualFileMeta;
      }
    >
  >(new Map());

  // Sync burnAfterPull state to ref so WebRTC callbacks always read fresh value
  useEffect(() => {
    burnAfterPullRef.current = burnAfterPull;
  }, [burnAfterPull]);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  };

  const broadcastToPeers = (payload: any, excludePeerId?: string) => {
    connectionsRef.current.forEach((conn) => {
      if (conn.open && conn.peer !== excludePeerId) {
        conn.send(payload);
      }
    });
  };

  // 🚀 SENDER ENGINE + 2-LEVEL EDGE-AI + AES-256-GCM + SHA-256 + BURN-ON-PULL
  const streamFileToPeer = async (
    fileId: string,
    mode: "download" | "preview" | "zip",
    targetConn: DataConnection
  ) => {
    const originalFile = localFileMapRef.current.get(fileId);
    if (!originalFile) return;

    let fileToStream: Blob = originalFile;
    const isTextOrCode =
      /\.(env|js|ts|tsx|jsx|json|py|md|txt|yml|yaml|css|html)$/i.test(originalFile.name) ||
      originalFile.name.startsWith(".env");
    const isImage = /\.(png|jpg|jpeg|webp)$/i.test(originalFile.name);

    // 🧠 LEVEL 1 AI SHIELD: ONNX Secret Scanner
    if (aiShieldEnabled && isTextOrCode && originalFile.size < 2 * 1024 * 1024) {
      setShieldLog(`🔍 Scanning ${originalFile.name} with ONNX Secret Model...`);
      const rawText = await originalFile.text();
      const { maskedText, secretsFound } = await scanAndMaskSecrets(rawText);

      if (secretsFound > 0) {
        fileToStream = new Blob([maskedText], { type: originalFile.type || "text/plain" });
        setShieldLog(`🛡️ ONNX Shield masked ${secretsFound} secret(s) in ${originalFile.name}!`);
      } else {
        setShieldLog(`✅ ${originalFile.name} passed ONNX scan (0 secrets).`);
      }
    }
    // 🖼️ LEVEL 2 AI SHIELD: WASM OCR Image PII Auto-Blur
    else if (aiShieldEnabled && isImage && originalFile.size < 15 * 1024 * 1024) {
      setShieldLog(`👁️ Running WASM OCR on ${originalFile.name} (takes ~3-5 sec)...`);
      const { redactedBlob, redactedCount } = await scanAndBlurImagePII(originalFile);

      if (redactedCount > 0) {
        fileToStream = redactedBlob;
        setShieldLog(`🛡️ OCR Shield censored ${redactedCount} sensitive item(s) in ${originalFile.name}!`);
      } else {
        setShieldLog(`✅ ${originalFile.name} passed OCR scan (0 PII found).`);
      }
    }

    // 🛡️ Compute SHA-256 Hash of outgoing sanitized stream for Zero-Tamper Integrity
    const fullBuffer = await fileToStream.arrayBuffer();
    const sha256Hash = await computeSHA256(fullBuffer);

    targetConn.send({
      type: "VFS_FILE_START",
      mode,
      sha256: sha256Hash,
      meta: {
        id: fileId,
        name: originalFile.name,
        path: originalFile.webkitRelativePath || originalFile.name,
        size: fileToStream.size,
        type: fileToStream.type || originalFile.type,
      },
    });

    let offset = 0;
    const rawDc = (targetConn as any).dataChannel as RTCDataChannel | undefined;

    while (offset < fullBuffer.byteLength) {
      if (rawDc && rawDc.bufferedAmount > 1024 * 1024) {
        await new Promise((r) => setTimeout(r, 15));
        continue;
      }

      const plainBuffer = fullBuffer.slice(offset, offset + CHUNK_SIZE);

      // 🔐 Encrypt 64KB chunk with AES-256-GCM before sending over WebRTC!
      if (cryptoKeyRef.current) {
        const { iv, cipherBuffer } = await encryptChunk(cryptoKeyRef.current, plainBuffer);
        targetConn.send({
          type: "VFS_FILE_CHUNK",
          fileId,
          encrypted: true,
          iv,
          chunk: cipherBuffer,
          byteLength: plainBuffer.byteLength,
        });
        setEncryptedChunksCount((prev) => prev + 1);
      } else {
        targetConn.send({
          type: "VFS_FILE_CHUNK",
          fileId,
          encrypted: false,
          chunk: plainBuffer,
          byteLength: plainBuffer.byteLength,
        });
      }

      offset += plainBuffer.byteLength;
      if ((offset / CHUNK_SIZE) % 16 === 0) {
        await new Promise((r) => setTimeout(r, 2));
      }
    }

    targetConn.send({ type: "VFS_FILE_END", fileId });

    // 🔥 FEATURE #4: BURN AFTER 1 PULL (Self-Destruct File after streaming!)
    if (burnAfterPullRef.current) {
      localFileMapRef.current.delete(fileId);
      const updatedTree = localMetaListRef.current.filter((f) => f.id !== fileId);
      localMetaListRef.current = updatedTree;
      setMyFiles(updatedTree);
      setShieldLog(`🔥 Self-Destruct: "${originalFile.name}" burned from Vault after 1 pull!`);

      broadcastToPeers({
        type: "VFS_TREE_SYNC",
        files: updatedTree,
        ownerPeerId: peerRef.current?.id,
      });
    }
  };

  // 🕸️ MULTI-PEER CONNECTION HANDLER
  const setupConnection = (conn: DataConnection) => {
    setStatus("connecting");

    conn.on("open", () => {
      if (!connectionsRef.current.some((c) => c.peer === conn.peer)) {
        connectionsRef.current.push(conn);
      }
      setPeerCount(connectionsRef.current.length);
      setStatus("connected");
      setErrorMsg("");

      // Sync our mounted VFS tree to this newly joined peer
      if (localMetaListRef.current.length > 0) {
        conn.send({
          type: "VFS_TREE_SYNC",
          files: localMetaListRef.current,
          ownerPeerId: peerRef.current?.id,
        });
      }
    });

    conn.on("data", async (rawData: any) => {
      if (!rawData || typeof rawData !== "object") return;

      switch (rawData.type) {
        case "CHAT": {
          const senderTag = rawData.senderId || conn.peer.slice(-4);
          setMessages((prev) => [...prev, { sender: `Peer-${senderTag}`, text: rawData.text }]);
          broadcastToPeers(
            { type: "CHAT", text: rawData.text, senderId: senderTag },
            conn.peer
          );
          break;
        }

        case "VFS_TREE_SYNC": {
          const incomingOwner = rawData.ownerPeerId || conn.peer;
          const incomingFiles: VirtualFileMeta[] = (rawData.files || []).map((f: VirtualFileMeta) => ({
            ...f,
            ownerPeerId: incomingOwner,
          }));

          setRemoteFiles((prev) => {
            const filtered = prev.filter((item) => item.ownerPeerId !== incomingOwner);
            return [...filtered, ...incomingFiles];
          });

          broadcastToPeers(
            { type: "VFS_TREE_SYNC", files: incomingFiles, ownerPeerId: incomingOwner },
            conn.peer
          );
          break;
        }

        case "VFS_FILE_REQ":
          if (localFileMapRef.current.has(rawData.fileId)) {
            streamFileToPeer(rawData.fileId, rawData.mode || "download", conn);
          }
          break;

        case "VFS_FILE_START": {
          const { meta, mode, sha256 } = rawData;
          incomingBuffersRef.current.set(meta.id, {
            chunks: [],
            receivedBytes: 0,
            startTime: performance.now(),
            mode: mode || "download",
            expectedHash: sha256,
            meta,
          });
          setDownloadProgress((prev) => ({ ...prev, [meta.id]: 1 }));
          break;
        }

        case "VFS_FILE_CHUNK": {
          const entry = incomingBuffersRef.current.get(rawData.fileId);
          if (!entry) break;

          let finalChunk: ArrayBuffer = rawData.chunk;
          if (rawData.encrypted && cryptoKeyRef.current && rawData.iv) {
            finalChunk = await decryptChunk(cryptoKeyRef.current, rawData.iv, rawData.chunk);
            setEncryptedChunksCount((prev) => prev + 1);
          }

          entry.chunks.push(finalChunk);
          entry.receivedBytes += rawData.byteLength;

          const elapsedSec = Math.max(0.05, (performance.now() - entry.startTime) / 1000);
          const bytesPerSec = entry.receivedBytes / elapsedSec;
          setTransferSpeed(`${formatBytes(bytesPerSec)}/s`);

          const percent = Math.min(
            99,
            Math.round((entry.receivedBytes / Math.max(1, entry.meta.size)) * 100)
          );
          setDownloadProgress((prev) => ({ ...prev, [rawData.fileId]: percent }));
          break;
        }

        case "VFS_FILE_END": {
          const entry = incomingBuffersRef.current.get(rawData.fileId);
          if (!entry) break;

          const blob = new Blob(entry.chunks, {
            type: entry.meta.type || "application/octet-stream",
          });

          // 🛡️ FEATURE #2: Verify SHA-256 Integrity Hash on Reassembled File!
          const combinedBuffer = await blob.arrayBuffer();
          const actualHash = await computeSHA256(combinedBuffer);
          const isHashMatch = !entry.expectedHash || entry.expectedHash === actualHash;

          if (isHashMatch) {
            setVerifiedHashes((prev) => ({
              ...prev,
              [rawData.fileId]: actualHash.slice(0, 8),
            }));
          }

          // Check mode: "zip", "preview", or normal "download"
          if (entry.mode === "zip" && zipCollectorRef.current.active) {
            zipCollectorRef.current.files.push({
              name: entry.meta.path || entry.meta.name,
              blob,
            });
            zipCollectorRef.current.pendingIds.delete(rawData.fileId);

            // If all requested files for the ZIP have arrived, build & download the .zip!
            if (zipCollectorRef.current.pendingIds.size === 0) {
              const JSZip = (await import("jszip")).default;
              const zip = new JSZip();
              zipCollectorRef.current.files.forEach((f) => {
                zip.file(f.name, f.blob);
              });
              const zipBlob = await zip.generateAsync({ type: "blob" });
              const url = URL.createObjectURL(zipBlob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `AirVault-${joinedRoom || "Bundle"}.zip`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);

              zipCollectorRef.current.active = false;
              zipCollectorRef.current.files = [];
              setIsZipping(false);
            }
          } else if (entry.mode === "preview") {
            const name = entry.meta.name;
            const isImg = /\.(png|jpg|jpeg|webp|gif)$/i.test(name);
            const isVid = /\.(mp4|webm|ogg|mov)$/i.test(name);
            const isAud = /\.(mp3|wav)$/i.test(name);
            const isPdf = /\.pdf$/i.test(name);
            const shortHash = actualHash.slice(0, 12);

            if (isImg) {
              setPreviewModal({ name, type: "image", content: URL.createObjectURL(blob), sha256: shortHash });
            } else if (isVid) {
              setPreviewModal({ name, type: "video", content: URL.createObjectURL(blob), sha256: shortHash });
            } else if (isAud) {
              setPreviewModal({ name, type: "audio", content: URL.createObjectURL(blob), sha256: shortHash });
            } else if (isPdf) {
              const pdfBlob = new Blob(entry.chunks, { type: "application/pdf" });
              setPreviewModal({ name, type: "pdf", content: URL.createObjectURL(pdfBlob), sha256: shortHash });
            } else {
              const text = await blob.text();
              setPreviewModal({ name, type: "text", content: text, sha256: shortHash });
            }
          } else {
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = entry.meta.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
          }

          incomingBuffersRef.current.delete(rawData.fileId);
          setDownloadProgress((prev) => ({ ...prev, [rawData.fileId]: 100 }));
          break;
        }
      }
    });

    conn.on("close", () => {
      connectionsRef.current = connectionsRef.current.filter((c) => c.peer !== conn.peer);
      setPeerCount(connectionsRef.current.length);
      setRemoteFiles((prev) => prev.filter((f) => f.ownerPeerId !== conn.peer));
      if (connectionsRef.current.length === 0) {
        setStatus("waiting");
      }
    });
  };

  // 1. CREATE ROOM
  const createRoom = async () => {
    setErrorMsg("");
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    setRoomId(code);
    setJoinedRoom(code);
    setStatus("waiting");

    cryptoKeyRef.current = await deriveRoomKey(code);

    const { Peer } = await import("peerjs");
    const peer = new Peer(`${ID_PREFIX}${code}`);
    peerRef.current = peer;

    peer.on("connection", (conn) => setupConnection(conn));
    peer.on("error", (err) => setErrorMsg(err.message));
  };

  // 2. JOIN ROOM
  const connectToRoomCode = async (rawCode: string) => {
    if (!rawCode.trim()) return;
    setErrorMsg("");
    const code = rawCode.trim().toUpperCase();
    setRoomId(code);
    setJoinedRoom(code);
    setStatus("connecting");

    cryptoKeyRef.current = await deriveRoomKey(code);

    const { Peer } = await import("peerjs");
    const peer = new Peer();
    peerRef.current = peer;

    peer.on("open", () => {
      const conn = peer.connect(`${ID_PREFIX}${code}`, { reliable: true });
      setupConnection(conn);
    });

    peer.on("connection", (conn) => setupConnection(conn));

    peer.on("error", () => {
      setErrorMsg("Room not found or host offline!");
      setStatus("waiting");
    });
  };

  const joinRoom = async (e: React.FormEvent) => {
    e.preventDefault();
    await connectToRoomCode(roomId);
  };

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const urlRoom = params.get("room");
      if (urlRoom && urlRoom.length === 6) {
        connectToRoomCode(urlRoom);
      }
    }
    return () => peerRef.current?.destroy();
  }, []);

  // 3A. UNIFIED MOUNT ENGINE (Supports Folder Mount, Single Files & Drag-and-Drop!)
  const processIncomingFileList = (fileList: FileList | File[]) => {
    const filesArray = Array.from(fileList);
    if (filesArray.length === 0) return;

    const virtualTree: VirtualFileMeta[] = [...localMetaListRef.current];
    const currentFileMap = localFileMapRef.current;
    let skipped = 0;

    filesArray.forEach((file, index) => {
      const relPath = file.webkitRelativePath || file.name;
      const pathParts = relPath.split("/");

      if (pathParts.some((part) => IGNORED_DIRS.includes(part))) {
        skipped++;
        return;
      }

      const fileId = `vf-${Date.now()}-${Math.random().toString(36).slice(2, 6)}-${index}`;
      currentFileMap.set(fileId, file);

      virtualTree.push({
        id: fileId,
        name: file.name,
        path: relPath,
        size: file.size,
        type: file.type || "unknown",
        ownerPeerId: peerRef.current?.id,
      });
    });

    localMetaListRef.current = virtualTree;
    setMyFiles(virtualTree);
    setIgnoredCount((prev) => prev + skipped);

    if (connectionsRef.current.length > 0) {
      broadcastToPeers({
        type: "VFS_TREE_SYNC",
        files: virtualTree,
        ownerPeerId: peerRef.current?.id,
      });
    }
  };

  const handleFolderMount = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) processIncomingFileList(e.target.files);
    e.target.value = "";
  };

  // Drag-and-Drop Handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processIncomingFileList(e.dataTransfer.files);
    }
  };

  // 3B. UNMOUNT VIRTUAL FOLDER
  const handleFolderUnmount = () => {
    localFileMapRef.current.clear();
    localMetaListRef.current = [];
    setMyFiles([]);
    setIgnoredCount(0);
    setShieldLog("🔒 Local files unmounted. Access revoked from all peers.");

    if (connectionsRef.current.length > 0) {
      broadcastToPeers({
        type: "VFS_TREE_SYNC",
        files: [],
        ownerPeerId: peerRef.current?.id,
      });
    }
  };

  // 4A. REQUEST SINGLE FILE
  const requestRemoteFile = (
    file: VirtualFileMeta,
    mode: "download" | "preview" | "zip" = "download"
  ) => {
    if (connectionsRef.current.length === 0) return;
    setDownloadProgress((prev) => ({ ...prev, [file.id]: 1 }));

    const targetConn =
      connectionsRef.current.find((c) => c.peer === file.ownerPeerId) ||
      connectionsRef.current[0];

    targetConn?.send({ type: "VFS_FILE_REQ", fileId: file.id, mode });
  };

  // 4B. FEATURE #1: 1-CLICK "PULL ALL AS .ZIP" IN-BROWSER BUNDLER
  const pullAllAsZip = () => {
    if (filteredRemoteFiles.length === 0 || isZipping) return;
    setIsZipping(true);

    const ids = new Set(filteredRemoteFiles.map((f) => f.id));
    zipCollectorRef.current = {
      active: true,
      pendingIds: ids,
      files: [],
    };

    filteredRemoteFiles.forEach((file) => {
      requestRemoteFile(file, "zip");
    });
  };

  // 5. GROUP CHAT BROADCAST
  const sendP2PMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!msgInput.trim() || connectionsRef.current.length === 0) return;

    const myTag = peerRef.current?.id.slice(-4) || "Host";
    broadcastToPeers({ type: "CHAT", text: msgInput, senderId: myTag });
    setMessages((prev) => [...prev, { sender: "Me", text: msgInput }]);
    setMsgInput("");
  };

  const copyShareLink = () => {
    const url = `${window.location.origin}/?room=${joinedRoom}`;
    navigator.clipboard.writeText(url);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const closePreviewModal = () => {
    if (previewModal && previewModal.type !== "text") {
      URL.revokeObjectURL(previewModal.content);
    }
    setPreviewModal(null);
  };

  const leaveRoom = () => {
    connectionsRef.current.forEach((c) => c.close());
    connectionsRef.current = [];
    peerRef.current?.destroy();
    localFileMapRef.current.clear();
    localMetaListRef.current = [];
    setJoinedRoom("");
    setStatus("idle");
    setPeerCount(0);
    setMessages([]);
    setMyFiles([]);
    setRemoteFiles([]);
    setDownloadProgress({});
    setVerifiedHashes({});
    if (typeof window !== "undefined") {
      window.history.replaceState({}, "", window.location.pathname);
    }
  };

  const filteredRemoteFiles = remoteFiles.filter((f) =>
    f.path.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const shareUrl =
    typeof window !== "undefined" ? `${window.location.origin}/?room=${joinedRoom}` : "";

  return (
    <main className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center p-4">
      <div className="flex items-center gap-2 mb-1 text-emerald-400">
        <Shield className="w-8 h-8" />
        <h1 className="text-3xl font-bold tracking-wider text-white">AirVault</h1>
      </div>
      <p className="text-slate-400 text-xs mb-6 flex items-center gap-2 text-center">
        <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        Multi-Peer WebRTC VFS • Edge-AI ONNX & WASM Shield • AES-256-GCM + SHA-256 Verified
      </p>

      {!joinedRoom ? (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl w-full max-w-md shadow-xl">
          <button
            onClick={createRoom}
            className="w-full bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold py-3 rounded-xl flex items-center justify-center gap-2 transition cursor-pointer"
          >
            <Sparkles className="w-5 h-5" /> Create Multi-Peer Vault (Room)
          </button>

          <div className="my-6 flex items-center gap-4 text-slate-600 text-xs uppercase">
            <div className="h-[1px] bg-slate-800 flex-1" /> OR{" "}
            <div className="h-[1px] bg-slate-800 flex-1" />
          </div>

          <form onSubmit={joinRoom} className="flex gap-2">
            <input
              type="text"
              placeholder="Enter 6-digit Room Code..."
              value={roomId}
              onChange={(e) => setRoomId(e.target.value.toUpperCase())}
              maxLength={6}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-emerald-500 uppercase tracking-widest"
            />
            <button
              type="submit"
              className="bg-slate-800 hover:bg-slate-700 px-4 rounded-xl flex items-center justify-center transition cursor-pointer"
            >
              <ArrowRight className="w-5 h-5 text-emerald-400" />
            </button>
          </form>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl w-full max-w-5xl shadow-xl">
          {/* Top Telemetry Bar */}
          <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-4 mb-5 gap-3">
            <div className="flex items-center gap-3">
              <div>
                <span className="text-[10px] uppercase tracking-widest text-slate-400 block">
                  Active Vault Code
                </span>
                <h2 className="text-2xl font-mono font-bold text-emerald-400 tracking-widest">
                  {joinedRoom}
                </h2>
              </div>

              <button
                onClick={() => setShowQrModal(true)}
                className="bg-slate-950 hover:bg-slate-800 border border-slate-800 px-3 py-2 rounded-xl text-xs flex items-center gap-1.5 text-emerald-400 transition cursor-pointer"
              >
                <QrCode className="w-4 h-4" />
                <span>Share / QR</span>
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              {/* Swarm Peer Count Badge */}
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-purple-500/10 border border-purple-500/30 text-xs text-purple-300 font-mono">
                <Users className="w-3.5 h-3.5" />
                <span>{peerCount} Peer(s)</span>
              </div>

              {/* AES-256-GCM Verified Counter Badge */}
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 font-mono">
                <Lock className="w-3.5 h-3.5" />
                <span>AES-256-GCM ({encryptedChunksCount})</span>
              </div>

              {/* Live Speedometer Badge */}
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-950 border border-slate-800 text-xs text-blue-400 font-mono">
                <Gauge className="w-3.5 h-3.5" />
                <span>{transferSpeed}</span>
              </div>

              {/* Connection Status Badge */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-950 border border-slate-800 text-xs">
                {status === "waiting" && (
                  <>
                    <Loader2 className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                    <span className="text-amber-400">Waiting for Peers...</span>
                  </>
                )}
                {status === "connecting" && (
                  <>
                    <Wifi className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
                    <span className="text-blue-400">Handshaking...</span>
                  </>
                )}
                {status === "connected" && (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400 font-medium">Swarm Active</span>
                  </>
                )}
              </div>

              <button
                onClick={leaveRoom}
                className="text-xs text-slate-400 hover:text-red-400 border border-slate-800 px-3 py-1.5 rounded-lg transition cursor-pointer"
              >
                Leave
              </button>
            </div>
          </div>

          {errorMsg && (
            <div className="mb-4 p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 text-center">
              {errorMsg}
            </div>
          )}

          {status === "connected" ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* LEFT 2 COLS: VFS Explorer & AI Controls */}
              <div className="md:col-span-2 space-y-3">
                {/* ✋ FEATURE #3: Drag & Drop Zone + Folder & Single File Mount */}
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`bg-slate-950 border-2 border-dashed p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 transition ${
                    isDragging
                      ? "border-emerald-400 bg-emerald-500/10"
                      : "border-slate-800"
                  }`}
                >
                  <div>
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <HardDrive className="w-4 h-4 text-emerald-400" />
                      Zero-Cloud VFS Mount (or Drag & Drop Files Here)
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Auto-filters <code className="text-amber-400">node_modules</code>,{" "}
                      <code className="text-amber-400">.git</code>,{" "}
                      <code className="text-amber-400">.next</code>
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Add Single/Multiple Files Button */}
                    <label className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold px-3.5 py-2.5 rounded-xl flex items-center gap-1.5 cursor-pointer transition">
                      <FileUp className="w-4 h-4 text-emerald-400" />
                      Add Files
                      <input
                        type="file"
                        multiple
                        onChange={handleFolderMount}
                        className="hidden"
                      />
                    </label>

                    {/* Mount Whole Folder Button */}
                    <label className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 text-xs font-semibold px-3.5 py-2.5 rounded-xl flex items-center gap-1.5 cursor-pointer transition">
                      <FolderUp className="w-4 h-4" />
                      Mount Folder
                      <input
                        type="file"
                        // @ts-ignore
                        webkitdirectory="true"
                        directory="true"
                        multiple
                        onChange={handleFolderMount}
                        className="hidden"
                      />
                    </label>
                  </div>
                </div>

                {/* Edge-AI Shield + 🔥 Burn After 1 Pull Control Bar */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <div className="bg-slate-950 border border-emerald-500/30 p-2.5 rounded-xl flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>
                        <b>Edge-AI Shield:</b> ONNX + OCR Blur
                      </span>
                    </div>
                    <button
                      onClick={() => setAiShieldEnabled(!aiShieldEnabled)}
                      className={`px-2.5 py-1 rounded-full font-semibold cursor-pointer transition ${
                        aiShieldEnabled
                          ? "bg-emerald-500 text-slate-950"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {aiShieldEnabled ? "ACTIVE" : "OFF"}
                    </button>
                  </div>

                  {/* 🔥 FEATURE #4: Burn After Reading Toggle */}
                  <div className="bg-slate-950 border border-orange-500/30 p-2.5 rounded-xl flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <Flame className="w-4 h-4 text-orange-400 shrink-0" />
                      <span>
                        <b>Burn After 1 Pull:</b> Self-Destruct
                      </span>
                    </div>
                    <button
                      onClick={() => setBurnAfterPull(!burnAfterPull)}
                      className={`px-2.5 py-1 rounded-full font-semibold cursor-pointer transition ${
                        burnAfterPull
                          ? "bg-orange-500 text-slate-950"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {burnAfterPull ? "ARMED 🔥" : "OFF"}
                    </button>
                  </div>
                </div>

                {/* Mounted Status Bar with UNMOUNT Button */}
                {myFiles.length > 0 && (
                  <div className="text-xs bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 px-3 py-2 rounded-lg flex items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-3">
                      <span>
                        ✅ Mounted <b>{myFiles.length}</b> file(s) to {peerCount} peer(s)
                      </span>
                      {ignoredCount > 0 && (
                        <span className="text-amber-400">🛡️ Ignored {ignoredCount} junk files</span>
                      )}
                    </div>

                    <button
                      onClick={handleFolderUnmount}
                      className="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-2.5 py-1 rounded-md text-[11px] flex items-center gap-1 cursor-pointer transition shrink-0"
                    >
                      <Trash2 className="w-3 h-3" /> Unmount All
                    </button>
                  </div>
                )}

                {shieldLog && (
                  <div className="text-xs bg-amber-500/10 border border-amber-500/30 text-amber-300 px-3 py-2 rounded-lg font-mono">
                    {shieldLog}
                  </div>
                )}

                {/* Remote Peers' File Tree */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 h-72 flex flex-col">
                  <div className="flex flex-wrap items-center justify-between mb-3 gap-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Folder className="w-4 h-4 text-blue-400" />
                      Shared Room Vault ({filteredRemoteFiles.length} files)
                    </h4>

                    <div className="flex items-center gap-2">
                      {/* 📦 FEATURE #1: 1-Click Download All as ZIP Button */}
                      {filteredRemoteFiles.length > 0 && (
                        <button
                          onClick={pullAllAsZip}
                          disabled={isZipping}
                          className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 px-2.5 py-1 rounded-lg text-xs flex items-center gap-1.5 cursor-pointer transition"
                        >
                          <Archive className="w-3.5 h-3.5" />
                          {isZipping ? "Bundling .ZIP..." : "Pull All (.zip)"}
                        </button>
                      )}

                      <div className="relative w-44">
                        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                        <input
                          type="text"
                          placeholder="Search files..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-2.5 py-1 text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
                    {filteredRemoteFiles.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-xs text-slate-600 text-center">
                        {remoteFiles.length === 0
                          ? "No peer has mounted files yet. Drag & drop files or click 'Mount Folder' in any tab!"
                          : "No files match your search."}
                      </div>
                    ) : (
                      filteredRemoteFiles.map((f) => {
                        const progress = downloadProgress[f.id] || 0;
                        const verifiedHash = verifiedHashes[f.id];
                        const canPreview =
                          /\.(env|js|ts|tsx|jsx|json|py|md|txt|yml|yaml|css|html|png|jpg|jpeg|webp|gif|mp4|webm|ogg|mov|mp3|wav|pdf)$/i.test(
                            f.name
                          ) || f.name.startsWith(".env");

                        return (
                          <div
                            key={f.id}
                            className="flex items-center justify-between bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800/60 px-3 py-2 rounded-lg text-xs transition"
                          >
                            <div className="flex items-center gap-2.5 truncate pr-3">
                              <FileText className="w-4 h-4 text-emerald-400 shrink-0" />
                              <div className="truncate">
                                <div className="flex items-center gap-2">
                                  <span className="text-slate-200 font-medium truncate">
                                    {f.name}
                                  </span>
                                  {/* 🛡️ FEATURE #2: SHA-256 Verified Badge */}
                                  {verifiedHash && (
                                    <span
                                      title={`SHA-256 Checksum Verified: ${verifiedHash}...`}
                                      className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-1.5 py-0.2 rounded flex items-center gap-0.5 font-mono shrink-0"
                                    >
                                      <ShieldCheck className="w-3 h-3" /> SHA-256
                                    </span>
                                  )}
                                </div>
                                <span className="text-[10px] text-slate-500 font-mono truncate block">
                                  {f.path}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-[11px] font-mono text-slate-400 mr-1">
                                {formatBytes(f.size)}
                              </span>

                              {canPreview && (
                                <button
                                  onClick={() => requestRemoteFile(f, "preview")}
                                  title="Live AI-Safe Preview in Browser"
                                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-2 py-1 rounded-md text-[11px] flex items-center gap-1 cursor-pointer transition"
                                >
                                  <Eye className="w-3 h-3 text-emerald-400" /> Preview
                                </button>
                              )}

                              {progress > 0 && progress < 100 ? (
                                <div className="w-16 bg-slate-800 rounded-full h-5 overflow-hidden relative flex items-center justify-center border border-blue-500/30">
                                  <div
                                    className="bg-blue-500/40 h-full absolute left-0 top-0 transition-all"
                                    style={{ width: `${progress}%` }}
                                  />
                                  <span className="text-[10px] font-mono text-blue-200 relative z-10">
                                    {progress}%
                                  </span>
                                </div>
                              ) : (
                                <button
                                  onClick={() => requestRemoteFile(f, "download")}
                                  className="bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/30 px-2.5 py-1 rounded-md text-[11px] flex items-center gap-1 cursor-pointer transition"
                                >
                                  <Download className="w-3 h-3" /> Pull
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>

              {/* RIGHT COL: Multi-Peer Group Chat */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col h-[460px]">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                  Swarm Room Chat ({peerCount + 1} online)
                </h4>

                <div className="flex-1 overflow-y-auto flex flex-col gap-2 text-xs mb-3 pr-1">
                  {messages.length === 0 ? (
                    <p className="text-slate-600 m-auto text-center">No messages yet.</p>
                  ) : (
                    messages.map((m, idx) => (
                      <div
                        key={idx}
                        className={`px-3 py-2 rounded-lg max-w-[85%] ${
                          m.sender === "Me"
                            ? "bg-emerald-500/20 border border-emerald-500/30 text-emerald-200 self-end"
                            : "bg-slate-800 text-slate-200 self-start"
                        }`}
                      >
                        <span className="text-[9px] opacity-60 block mb-0.5">{m.sender}</span>
                        {m.text}
                      </div>
                    ))
                  )}
                </div>

                <form onSubmit={sendP2PMessage} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Broadcast to room..."
                    value={msgInput}
                    onChange={(e) => setMsgInput(e.target.value)}
                    className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    type="submit"
                    className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 px-3 rounded-lg flex items-center justify-center transition cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500 space-y-3">
              <p>
                Open <span className="text-slate-300 font-mono">localhost:3000</span> in multiple
                tabs and enter code <span className="text-emerald-400 font-bold">{joinedRoom}</span>
              </p>
              <button
                onClick={copyShareLink}
                className="mx-auto bg-slate-950 hover:bg-slate-800 border border-slate-800 px-4 py-2 rounded-xl text-xs flex items-center gap-2 text-emerald-400 transition cursor-pointer"
              >
                {copiedLink ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copiedLink ? "Auto-Join Link Copied!" : "Copy 1-Click Auto-Join Link"}
              </button>
            </div>
          )}
        </div>
      )}

      {/* 📱 QR CODE & 1-CLICK SHARE MODAL */}
      {showQrModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-sm w-full p-6 text-center shadow-2xl relative">
            <button
              onClick={() => setShowQrModal(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-white mb-1">Multi-Peer Room Invite</h3>
            <p className="text-xs text-slate-400 mb-4">
              Multiple devices can scan & join this Vault simultaneously!
            </p>

            <div className="bg-white p-3 rounded-xl inline-block mb-4">
              <img
                src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(
                  shareUrl
                )}`}
                alt="Vault QR Code"
                className="w-44 h-44"
              />
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-2.5 flex items-center justify-between gap-2 text-xs">
              <span className="font-mono text-slate-300 truncate">{shareUrl}</span>
              <button
                onClick={copyShareLink}
                className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold px-3 py-1.5 rounded-lg shrink-0 flex items-center gap-1 cursor-pointer"
              >
                {copiedLink ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedLink ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 👁️ ZERO-DOWNLOAD LIVE PREVIEW MODAL */}
      {previewModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950">
              <div className="flex flex-wrap items-center gap-2">
                <Eye className="w-4 h-4 text-emerald-400" />
                <span className="text-sm font-mono font-semibold text-white">
                  {previewModal.name}
                </span>
                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                  AES-256-GCM Decrypted
                </span>
                {previewModal.sha256 && (
                  <span className="text-[10px] bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full font-mono">
                    SHA-256: {previewModal.sha256}...
                  </span>
                )}
              </div>
              <button
                onClick={closePreviewModal}
                className="text-slate-400 hover:text-white p-1 rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 overflow-y-auto flex-1 bg-slate-950 flex flex-col justify-center">
              {previewModal.type === "image" && (
                <img
                  src={previewModal.content}
                  alt={previewModal.name}
                  className="max-h-[65vh] mx-auto rounded-lg border border-slate-800"
                />
              )}

              {previewModal.type === "video" && (
                <video
                  src={previewModal.content}
                  controls
                  autoPlay
                  className="max-h-[65vh] w-full mx-auto rounded-lg border border-slate-800 bg-black"
                />
              )}

              {previewModal.type === "audio" && (
                <div className="py-12 flex flex-col items-center gap-4">
                  <p className="text-xs text-slate-400 font-mono">
                    🎵 Streaming Encrypted Audio from Peer Memory...
                  </p>
                  <audio src={previewModal.content} controls autoPlay className="w-full max-w-md" />
                </div>
              )}

              {previewModal.type === "pdf" && (
                <iframe
                  src={previewModal.content}
                  title={previewModal.name}
                  className="w-full h-[70vh] rounded-lg border border-slate-800 bg-white"
                />
              )}

              {previewModal.type === "text" && (
                <pre className="text-xs font-mono text-emerald-300 whitespace-pre-wrap leading-relaxed">
                  {previewModal.content}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}