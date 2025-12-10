import React, { useState, useEffect } from 'react';
import { Search, Shield, Lock, Eye, Code, Terminal, AlertCircle, CheckCircle2, Server, Globe, FileWarning, Bug, ScanSearch, Binary, Hash, ArrowRightLeft, Maximize } from 'lucide-react';

// --- Constants & Maps ---

const KEM_MAP = {
  0x0020: 'DHKEM(X25519, HKDF-SHA256)',
  0x0021: 'DHKEM(P-256, HKDF-SHA256)',
  0x0022: 'DHKEM(P-384, HKDF-SHA384)',
  0x0023: 'DHKEM(P-521, HKDF-SHA512)',
};

const CIPHER_MAP = {
  0x0001: 'AES_128_GCM_SHA256',
  0x0002: 'AES_256_GCM_SHA384',
  0x0003: 'CHACHA20_POLY1305_SHA256',
};

const VERSION_MAP = {
  0xFE0D: 'Draft-13',
  0xFE0C: 'Draft-12',
  0xFE0B: 'Draft-11',
};

// --- Helper Functions ---

const base64ToUint8Array = (base64) => {
  let clean = base64.replace(/[\s\n\r"']/g, '');
  clean = clean.replace(/-/g, '+').replace(/_/g, '/');
  while (clean.length % 4) {
    clean += '=';
  }

  try {
    const binaryString = window.atob(clean);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (e) {
    throw new Error(`Base64 decoding failed: ${e.message}`);
  }
};

const toHex = (num, pad = 2) => num.toString(16).padStart(pad, '0').toUpperCase();

const bufferToHex = (buffer) => {
  return Array.from(buffer).map(b => toHex(b)).join(' ');
};

const formatHexDump = (uint8Array) => {
    let output = '';
    const bytes = Array.from(uint8Array);
    for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i + 16);
        const hex = chunk.map(b => toHex(b)).join(' ');
        const ascii = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
        output += `${toHex(i, 4)}: ${hex.padEnd(47, ' ')}  |${ascii}|\n`;
    }
    return output;
};

// --- ECH Parser Logic ---

class BinaryReader {
  constructor(uint8Array) {
    this.data = uint8Array;
    this.offset = 0;
  }

  checkBounds(length) {
    if (this.offset + length > this.data.length) {
      throw new Error(`Buffer overflow: Need ${length} bytes, but only ${this.data.length - this.offset} remaining at offset ${this.offset}.`);
    }
  }

  readUint8() {
    this.checkBounds(1);
    return this.data[this.offset++];
  }

  readUint16() {
    this.checkBounds(2);
    const val = (this.data[this.offset] << 8) | this.data[this.offset + 1];
    this.offset += 2;
    return val;
  }

  readBytes(length) {
    this.checkBounds(length);
    const slice = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  remaining() {
    return this.data.length - this.offset;
  }
}

// Single pass parser that throws if invalid
const attemptParse = (bytes, startOffset) => {
    const reader = new BinaryReader(bytes);
    reader.offset = startOffset;
    
    let listLengthHex = null;
    let listLength = null;

    // Heuristic: If bytes[start] is NOT a version, try reading 2 bytes (Length Prefix)
    const firstTwo = (bytes[startOffset] << 8) | bytes[startOffset + 1];
    if ((firstTwo & 0xFF00) !== 0xFE00) {
        const lenBytes = reader.readBytes(2);
        listLength = (lenBytes[0] << 8) | lenBytes[1];
        listLengthHex = bufferToHex(lenBytes);
    }

    const configs = [];

    while (reader.remaining() > 0) {
      if (reader.remaining() < 4) break;

      // Read Version (2 bytes)
      const versionBytes = reader.readBytes(2);
      const version = (versionBytes[0] << 8) | versionBytes[1];
      
      // Strict Version Check
      if (!VERSION_MAP[version]) {
          throw new Error(`Unknown ECH version: 0x${toHex(version, 4)} at offset ${reader.offset - 2}`);
      }

      // Read Config Length (2 bytes)
      const lengthBytes = reader.readBytes(2);
      const length = (lengthBytes[0] << 8) | lengthBytes[1];
      
      // Strict Length Check
      if (length > reader.remaining()) {
          throw new Error(`Config length (${length}) exceeds remaining buffer (${reader.remaining()})`);
      }

      const contentsBytes = reader.readBytes(length);
      const contentReader = new BinaryReader(contentsBytes);
      
      // 1. Key Config ID (1 byte)
      const keyConfigIdBytes = contentReader.readBytes(1);
      const keyConfigId = keyConfigIdBytes[0];

      // 2. KEM ID (2 bytes)
      const kemBytes = contentReader.readBytes(2);
      const kemId = (kemBytes[0] << 8) | kemBytes[1];
      
      // 3. Public Key (Length prefixed 2 bytes + Bytes)
      const pubKeyLenBytes = contentReader.readBytes(2);
      const pubKeyLen = (pubKeyLenBytes[0] << 8) | pubKeyLenBytes[1];
      
      if (pubKeyLen > contentReader.remaining()) {
          throw new Error(`Invalid public key length: ${pubKeyLen}`);
      }
      
      const publicKey = contentReader.readBytes(pubKeyLen); 
      // Combine length prefix and key for raw hex display
      const fullPublicKeyBytes = new Uint8Array(2 + publicKey.length);
      fullPublicKeyBytes.set(pubKeyLenBytes);
      fullPublicKeyBytes.set(publicKey, 2);

      // 4. Cipher Suites (Length prefixed 2 bytes + Bytes)
      const cipherSuitesLenBytes = contentReader.readBytes(2);
      const cipherSuitesLen = (cipherSuitesLenBytes[0] << 8) | cipherSuitesLenBytes[1];

      if (cipherSuitesLen % 2 !== 0 || cipherSuitesLen > contentReader.remaining()) {
          throw new Error(`Invalid cipher suites length: ${cipherSuitesLen}`);
      }

      const cipherBytes = contentReader.readBytes(cipherSuitesLen);
      // Combine length prefix and suites for raw hex display
      const fullCipherBytes = new Uint8Array(2 + cipherBytes.length);
      fullCipherBytes.set(cipherSuitesLenBytes);
      fullCipherBytes.set(cipherBytes, 2);

      const cipherSuites = [];
      for(let i=0; i<cipherBytes.length; i+=2) {
          const cipherId = (cipherBytes[i] << 8) | cipherBytes[i+1];
          cipherSuites.push({
              id: cipherId,
              name: CIPHER_MAP[cipherId] || 'Unknown'
          });
      }

      // 5. Max Name Length (1 byte)
      const maxNameLenBytes = contentReader.readBytes(1);
      const maxNameLen = maxNameLenBytes[0];
      
      // 6. Public Name (Length prefixed 1 byte + Bytes)
      const publicNameLenBytes = contentReader.readBytes(1);
      const publicNameLen = publicNameLenBytes[0];
      
      let publicName = "";
      let publicNameBytes = new Uint8Array(0);

      if (publicNameLen > 0) {
          publicNameBytes = contentReader.readBytes(publicNameLen);
          publicName = new TextDecoder().decode(publicNameBytes);
      }
      
      // Combine length prefix and name for raw hex display
      const fullPublicNameBytes = new Uint8Array(1 + publicNameBytes.length);
      fullPublicNameBytes.set(publicNameLenBytes);
      fullPublicNameBytes.set(publicNameBytes, 1);

      configs.push({
        version: version,
        versionStr: VERSION_MAP[version] || 'Unknown',
        versionHex: bufferToHex(versionBytes),

        configLength: length,
        configLengthHex: bufferToHex(lengthBytes),

        keyConfigId: keyConfigId,
        keyConfigIdHex: bufferToHex(keyConfigIdBytes),

        kemId: kemId,
        kemStr: KEM_MAP[kemId] || `Unknown (0x${toHex(kemId, 4)})`,
        kemHex: bufferToHex(kemBytes),

        publicKey: bufferToHex(publicKey),
        publicKeyFullHex: bufferToHex(fullPublicKeyBytes),
        
        cipherSuites: cipherSuites,
        cipherSuitesFullHex: bufferToHex(fullCipherBytes),

        maxNameLen: maxNameLen,
        maxNameLenHex: bufferToHex(maxNameLenBytes),

        publicName: publicName,
        publicNameFullHex: bufferToHex(fullPublicNameBytes),
        
        rawHex: bufferToHex(contentsBytes)
      });
    }
    
    return { listLengthHex, configs };
};

const parseECHConfig = (base64String) => {
  let bytes;
  try {
    bytes = base64ToUint8Array(base64String);
  } catch (e) {
    return { parsed: null, error: e.message, debugData: null };
  }

  // --- Robust Scanning Strategy ---
  const possibleOffsets = [];
  possibleOffsets.push(0);
  
  for (let i = 0; i < bytes.length - 1; i++) {
      if (bytes[i] === 0xFE && (bytes[i+1] === 0x0D || bytes[i+1] === 0x0C)) {
          if (i >= 2) possibleOffsets.push(i - 2); 
          possibleOffsets.push(i); 
      }
  }

  const uniqueOffsets = [...new Set(possibleOffsets)];
  
  let lastError = null;

  for (const offset of uniqueOffsets) {
      try {
          const result = attemptParse(bytes, offset);
          if (result && result.configs.length > 0) {
              return { parsed: result, error: null, debugData: bytes, offsetUsed: offset };
          }
      } catch (e) {
          lastError = e;
      }
  }

  return { parsed: null, error: lastError ? lastError.message : "No valid ECH config found", debugData: bytes };
};

// --- Components ---

const InfoItem = ({ label, value, subValue, rawHex, icon: Icon, color = "text-gray-300" }) => (
  <div className="flex items-start p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:bg-slate-800 transition-colors">
    {Icon && <Icon className={`w-5 h-5 mt-0.5 mr-3 ${color}`} />}
    <div className="flex-1 overflow-hidden">
      <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">{label}</div>
      <div className="font-mono text-sm text-white break-all">{value}</div>
      {subValue && <div className="text-xs text-slate-500 mt-1">{subValue}</div>}
      {rawHex && (
        <div className="mt-2 flex items-center gap-2">
            <span className="text-[10px] uppercase text-slate-600 font-bold tracking-wider flex-shrink-0">Hex Raw:</span>
            <div className="font-mono text-[10px] text-slate-400 bg-slate-950/50 px-1.5 py-0.5 rounded break-all select-all border border-slate-800/50">
                {rawHex}
            </div>
        </div>
      )}
    </div>
  </div>
);

const HexView = ({ data, label }) => (
    <div className="mt-2">
        {label && <div className="text-[10px] uppercase text-slate-600 font-bold tracking-wider mb-1">{label}</div>}
        <div className="font-mono text-xs text-slate-400 bg-slate-950 p-3 rounded border border-slate-800 overflow-x-auto leading-relaxed select-all">
            {data}
        </div>
    </div>
);

export default function DNSVisualizer() {
  const [domain, setDomain] = useState('crypto.cloudflare.com');
  const [manualMode, setManualMode] = useState(false);
  const [manualInput, setManualInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [rawRecord, setRawRecord] = useState(null);
  const [echData, setEchData] = useState(null); 
  const [echError, setEchError] = useState(null);
  const [debugData, setDebugData] = useState(null);
  const [usedOffset, setUsedOffset] = useState(0);
  const [error, setError] = useState(null);
  const [params, setParams] = useState({});

  useEffect(() => {
      if (params.ech && !manualMode) {
          setManualInput(params.ech);
      }
  }, [params.ech]);

  const processECH = (echString) => {
      if (!echString) return;
      setEchError(null);
      setEchData(null);
      setDebugData(null);
      setUsedOffset(0);
      
      const { parsed, error, debugData, offsetUsed } = parseECHConfig(echString);
      setDebugData(debugData);
      setUsedOffset(offsetUsed);
      
      if (error) {
          setEchError(error);
      } else {
          setEchData(parsed);
      }
  };

  const fetchDNS = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);
    setEchError(null);
    setRawRecord(null);
    setEchData(null);
    setDebugData(null);
    setParams({});

    try {
      const response = await fetch(`https://dns.google/resolve?name=${domain}&type=HTTPS`);
      const data = await response.json();

      if (data.Status !== 0) {
        throw new Error(`DNS Query failed with status code: ${data.Status}`);
      }

      if (!data.Answer || data.Answer.length === 0) {
        throw new Error("No HTTPS records found for this domain.");
      }

      const record = data.Answer.find(r => r.type === 65);
      if (!record) {
        throw new Error("No HTTPS record found in answer.");
      }

      setRawRecord(record.data);

      const parts = record.data.split(' ');
      const extractedParams = {};
      
      parts.forEach(part => {
        if (part.includes('=')) {
            const [key, val] = part.split('=');
            extractedParams[key] = val.replace(/["']/g, ''); 
        }
      });

      setParams(extractedParams);

      if (extractedParams.ech) {
        processECH(extractedParams.ech);
      }

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleManualProcess = () => {
      setRawRecord("Manual Input Mode");
      setParams({ ech: manualInput });
      processECH(manualInput);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-4 md:p-8 font-sans">
      <div className="max-w-4xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="text-center space-y-2 mb-8">
          <h1 className="text-3xl md:text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400 inline-flex items-center gap-3">
            <Shield className="w-10 h-10 text-emerald-400" />
            HTTPS Record & ECH Decoder
          </h1>
          <p className="text-slate-400">
            可视化查询域名的 HTTPS 记录并解码 Encrypted Client Hello 字段
          </p>
        </div>

        {/* Input Controls */}
        <div className="bg-slate-800 p-4 rounded-xl shadow-lg border border-slate-700 space-y-4">
             {/* Toggle Mode */}
             <div className="flex justify-center space-x-4 border-b border-slate-700 pb-4">
                 <button 
                    onClick={() => setManualMode(false)}
                    className={`text-sm font-medium px-4 py-2 rounded-lg transition-colors ${!manualMode ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'}`}
                 >
                    通过域名查询
                 </button>
                 <button 
                    onClick={() => setManualMode(true)}
                    className={`text-sm font-medium px-4 py-2 rounded-lg transition-colors ${manualMode ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'}`}
                 >
                    手动输入 Base64
                 </button>
             </div>

             {/* Dynamic Input Area */}
             {!manualMode ? (
                 <div className="flex flex-col md:flex-row gap-4 animate-in fade-in">
                    <div className="relative flex-1">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Globe className="h-5 w-5 text-slate-500" />
                        </div>
                        <input
                        type="text"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && fetchDNS()}
                        className="block w-full pl-10 pr-3 py-3 border border-slate-600 rounded-lg leading-5 bg-slate-900 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 sm:text-sm text-white"
                        placeholder="Enter domain (e.g. crypto.cloudflare.com)"
                        />
                    </div>
                    <button
                        onClick={fetchDNS}
                        disabled={loading}
                        className="flex items-center justify-center px-6 py-3 border border-transparent text-sm font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 transition-colors"
                    >
                        {loading ? 'Processing...' : <><Search className="w-4 h-4 mr-2" /> 解析记录</>}
                    </button>
                 </div>
             ) : (
                 <div className="flex flex-col gap-4 animate-in fade-in">
                    <textarea
                        value={manualInput}
                        onChange={(e) => setManualInput(e.target.value)}
                        className="block w-full p-3 border border-slate-600 rounded-lg leading-5 bg-slate-900 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 sm:text-sm text-white font-mono text-xs h-24"
                        placeholder="Paste base64 ech string here..."
                    />
                    <button
                        onClick={handleManualProcess}
                        className="self-end px-6 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-green-600 hover:bg-green-700 transition-colors"
                    >
                        <Code className="w-4 h-4 inline mr-2" /> 解码 Base64
                    </button>
                 </div>
             )}
        </div>

        {/* Global Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800/50 p-4 rounded-lg flex items-center text-red-200">
            <AlertCircle className="w-5 h-5 mr-3 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Main Content Grid */}
        {(rawRecord || echData || echError) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Left Column: Data Source */}
            <div className="space-y-6">
              <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg">
                <div className="px-4 py-3 bg-slate-800 border-b border-slate-700 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  <h3 className="font-semibold text-slate-200">原始数据来源</h3>
                </div>
                <div className="p-4 bg-slate-950 font-mono text-xs text-green-400 break-all leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto">
                  {rawRecord}
                </div>
              </div>

              {debugData && (
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg">
                    <div className="px-4 py-3 bg-slate-800 border-b border-slate-700 flex items-center gap-2">
                        <Binary className="w-4 h-4 text-orange-400" />
                        <h3 className="font-semibold text-slate-200">ECH 原始字节流 (Hex)</h3>
                    </div>
                    <div className="bg-slate-950 p-4">
                        <pre className="font-mono text-[10px] text-slate-500 overflow-x-auto whitespace-pre leading-snug">
                            {formatHexDump(debugData)}
                        </pre>
                    </div>
                </div>
              )}
              
              {Object.keys(params).length > 0 && (
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg">
                    <div className="px-4 py-3 bg-slate-800 border-b border-slate-700 flex items-center gap-2">
                    <Server className="w-4 h-4 text-purple-400" />
                    <h3 className="font-semibold text-slate-200">提取参数</h3>
                    </div>
                    <div className="p-4 space-y-2">
                        {Object.entries(params).filter(([k]) => k !== 'ech').map(([key, value]) => (
                            <div key={key} className="flex flex-col gap-1 p-2 bg-slate-900/50 rounded border border-slate-700/50">
                                <span className="text-sm font-medium text-slate-400">{key}</span>
                                <span className="font-mono text-sm text-blue-300 break-all whitespace-pre-wrap">{value}</span>
                            </div>
                        ))}
                         {params.ech && (
                            <div className="flex flex-col gap-1 p-2 bg-slate-900/50 rounded border border-slate-700/50">
                                <span className="text-sm font-medium text-slate-400 mb-1">ech (Base64)</span>
                                <span className="font-mono text-xs text-yellow-500 break-all">{params.ech}</span>
                            </div>
                        )}
                    </div>
                </div>
              )}
            </div>

            {/* Right Column: Decoder Output */}
            <div className="space-y-6">
               <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg flex flex-col h-full">
                <div className="px-4 py-3 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-emerald-400" />
                    <h3 className="font-semibold text-slate-200">ECH 解码详情</h3>
                  </div>
                  {echData && <span className="text-xs bg-emerald-900/50 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800">Success</span>}
                </div>

                <div className="p-4 space-y-4 flex-1 overflow-y-auto max-h-[800px]">
                  {echError ? (
                     <div className="space-y-4">
                        <div className="bg-red-950/50 border border-red-900/50 rounded p-4 text-center">
                            <FileWarning className="w-8 h-8 mx-auto text-red-400 mb-2" />
                            <h4 className="text-red-300 font-medium mb-1">解析失败</h4>
                            <p className="text-xs text-red-400/80 font-mono break-all">{echError}</p>
                        </div>
                        {debugData && (
                            <div className="bg-slate-950 p-4 rounded border border-slate-800">
                                <div className="flex items-center gap-2 text-slate-400 mb-2 border-b border-slate-800 pb-2">
                                    <Bug className="w-4 h-4" />
                                    <span className="text-xs font-bold uppercase">Debug Hex Dump</span>
                                </div>
                                <pre className="font-mono text-[10px] text-slate-500 overflow-x-auto overflow-y-auto max-h-96 whitespace-pre leading-snug">
                                    {formatHexDump(debugData)}
                                </pre>
                            </div>
                        )}
                     </div>
                  ) : echData ? (
                    <div>
                        {usedOffset > 0 && (
                            <div className="mb-4 flex items-center gap-2 text-xs bg-yellow-900/30 text-yellow-200 p-2 rounded border border-yellow-700/30">
                                <ScanSearch className="w-4 h-4" />
                                <span>检测到非标准头部，已自动偏移 {usedOffset} 字节进行解码。</span>
                            </div>
                        )}
                        
                        {/* Render Global List Length if present */}
                        {echData.listLengthHex && (
                             <div className="mb-4 space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
                                <InfoItem 
                                    label="Total List Length" 
                                    value="ECH Config List Header" 
                                    rawHex={echData.listLengthHex}
                                    icon={Hash}
                                    color="text-slate-400"
                                />
                             </div>
                        )}

                        {echData.configs.map((config, idx) => (
                        <div key={idx} className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
                            <div className="flex items-center gap-2 mb-2">
                                <span className="text-xs font-bold text-slate-500 bg-slate-900 px-2 py-1 rounded">Config #{idx + 1}</span>
                            </div>
                            
                            {/* 1. Version */}
                            <InfoItem 
                                label="Version" 
                                value={`${config.versionStr} (0x${toHex(config.version, 4)})`} 
                                rawHex={config.versionHex}
                                icon={CheckCircle2}
                                color="text-blue-400"
                            />
                            
                            {/* 2. Config Length */}
                            <InfoItem 
                                label="Config Length" 
                                value={`${config.configLength} bytes`} 
                                rawHex={config.configLengthHex}
                                icon={Hash}
                                color="text-slate-400"
                            />

                            {/* 3. Key Config ID */}
                            <InfoItem 
                                label="Key Config ID" 
                                value={`0x${toHex(config.keyConfigId)}`} 
                                rawHex={config.keyConfigIdHex}
                                icon={Hash}
                                color="text-blue-400"
                            />

                            {/* 4. KEM ID */}
                            <InfoItem 
                                label="KEM 算法" 
                                value={config.kemStr} 
                                rawHex={config.kemHex}
                                icon={Code}
                                color="text-purple-400"
                            />
                            
                            {/* 5. Public Key (Moved before Cipher Suites based on byte stream) */}
                             <div>
                                <div className="text-xs font-medium text-slate-400 mb-1 flex items-center gap-2">
                                    <Binary className="w-3 h-3 text-emerald-400" />
                                    Public Key (Hex)
                                </div>
                                <div className="text-[10px] uppercase text-slate-600 font-bold tracking-wider mb-1">
                                    Len: {toHex(config.publicKey.length / 2, 4)} ({config.publicKey.length/2})
                                </div>
                                <HexView data={config.publicKeyFullHex} label="Length Prefix + Key Data" />
                            </div>

                            {/* 6. Cipher Suites */}
                            <InfoItem 
                                label="Cipher Suites" 
                                value={
                                    <div className="flex flex-col gap-1">
                                        {config.cipherSuites.map((cs, i) => (
                                            <span key={i} className="text-xs bg-slate-700 px-1.5 py-0.5 rounded w-fit">
                                                {cs.name} (0x{toHex(cs.id, 4)})
                                            </span>
                                        ))}
                                    </div>
                                } 
                                rawHex={config.cipherSuitesFullHex}
                                icon={Lock}
                                color="text-red-400"
                            />

                            {/* 7. Max Name Length */}
                             <InfoItem 
                                label="Max Name Length" 
                                value={`${config.maxNameLen} bytes`} 
                                rawHex={config.maxNameLenHex}
                                icon={Maximize}
                                color="text-slate-400"
                            />

                            {/* 8. Public Name */}
                            <InfoItem 
                                label="Public Name (伪装身份)" 
                                value={config.publicName} 
                                rawHex={config.publicNameFullHex}
                                subValue="握手初期使用的明文 SNI"
                                icon={Eye}
                                color="text-yellow-400"
                            />
                        </div>
                        ))}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-slate-500">等待输入...</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}