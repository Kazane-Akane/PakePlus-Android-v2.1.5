function togglePassword() {
    const pwdInput = document.getElementById('password');
    const isChecked = document.getElementById('showPwd').checked;
    pwdInput.type = isChecked ? "text" : "password";
}

const dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

function formatKey(inputPwd, targetLen, padByte) {
    let pwdBytes = new TextEncoder().encode(inputPwd);
    let res = new Uint8Array(targetLen);
    if (pwdBytes.length >= targetLen) {
        res.set(pwdBytes.slice(0, targetLen));
    } else {
        res.set(pwdBytes);
        for (let i = pwdBytes.length; i < targetLen; i++) res[i] = padByte;
    }
    return res;
}

function u8ToWA(u8Array) {
    const words = [];
    for (let i = 0; i < u8Array.length; i += 4) {
        words.push((u8Array[i] << 24) | (u8Array[i + 1] << 16) | (u8Array[i + 2] << 8) | (u8Array[i + 3]));
    }
    return CryptoJS.lib.WordArray.create(words, u8Array.length);
}

function wordToUint8(wordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    for (let i = 0; i < l; i++) {
        result[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return result;
}

function dataXor(data, key) {
    const keyBytes = (key instanceof Uint8Array) ? key : new TextEncoder().encode(key);
    if (keyBytes.length === 0) return data;
    const res = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        res[i] = data[i] ^ keyBytes[i % keyBytes.length];
    }
    return res;
}

function generateRandomIv(length) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let ret = "";
    for (let i = 0; i < length; i++) ret += charset.charAt(Math.floor(Math.random() * charset.length));
    return ret;
}

let currentFile = null;
let isDecryptMode = false;
const mainBtn = document.getElementById('mainBtn');
const fileNameDisp = document.getElementById('fileNameDisp');
const progress = document.getElementById('progress');
const logBox = document.getElementById('log');

const logger = (msg) => { 
    logBox.innerText += `\n> ${msg}`; 
    // 移动端滚动条平滑处理
    requestAnimationFrame(() => {
        logBox.scrollTop = logBox.scrollHeight; 
    });
};

document.getElementById('fileInput').onchange = (e) => {
    if (e.target.files.length) handleFileSelect(e.target.files[0]);
};

async function handleFileSelect(file) {
    currentFile = file;
    fileNameDisp.innerText = `已选: ${file.name}`;
    
    const customNameInput = document.getElementById('customName');
    const originalName = file.name;
    const lastDotIndex = originalName.lastIndexOf('.');
    let baseName = (lastDotIndex !== -1) ? originalName.substring(0, lastDotIndex) : originalName;

    const head = new Uint8Array(await file.slice(0, 12).arrayBuffer());
    const headStr = new TextDecoder().decode(head);

    if (headStr === "KazaneCrypto") {
        isDecryptMode = true;
        mainBtn.innerText = "立即解密";
        mainBtn.style.background = "#22c55e";
        if (baseName.toLowerCase().endsWith('.kazanecrypto')) {
            baseName = baseName.substring(0, baseName.length - 14);
        }
    } else {
        isDecryptMode = false;
        mainBtn.innerText = "立即加密";
        mainBtn.style.background = "#3b82f6";
    }
    
    customNameInput.value = baseName;
    mainBtn.disabled = false;
    logger(`文件已就绪: ${file.name}`);
}

async function handleAction() {
    const pwd = document.getElementById('password').value;
    if (!pwd) return alert("请输入密码");
    if (isDecryptMode) await runDecrypt(currentFile, pwd);
    else await runEncrypt(currentFile, pwd);
}

async function runEncrypt(file, pwdInput) {
    const algo = parseInt(document.getElementById('algoSelect').value);
    const sliceSize = 5 * 1024 * 1024;
    try {
        const firstChunkBuffer = await file.slice(0, sliceSize).arrayBuffer();
        const fileMd5 = CryptoJS.MD5(u8ToWA(new Uint8Array(firstChunkBuffer))).toString().toLowerCase();

        const rawHead = new Uint8Array(64);
        const ivStr = generateRandomIv(16);
        rawHead.set(new TextEncoder().encode(ivStr), 0);
        rawHead.set(new TextEncoder().encode(fileMd5), 16);
        rawHead[48] = algo & 0xff;
        const extBytes = new TextEncoder().encode(file.name.split('.').pop() || "bin");
        rawHead[52] = extBytes.length & 0xff;
        rawHead.set(extBytes, 56);

        const headerKeyWA = u8ToWA(formatKey(pwdInput, 32, 48));
        const headerIvWA = u8ToWA(new Uint8Array([56, 48, 50, 52, 75, 83, 65, 50, 52, 54, 56, 79, 87, 69, 54, 56]));
        const encHead = CryptoJS.AES.encrypt(u8ToWA(rawHead), headerKeyWA, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding, iv: headerIvWA });
        
        const finalHead = new Uint8Array(13 + 64);
        finalHead.set(new TextEncoder().encode("KazaneCrypto"), 0);
        finalHead[12] = 64;
        finalHead.set(wordToUint8(encHead.ciphertext), 13);

        const dataKeyRaw = formatKey(pwdInput, 32, 0);
        const dataKeyWA = u8ToWA(dataKeyRaw);
        const initialIvWA = u8ToWA(new TextEncoder().encode(ivStr));

        let encryptedChunks = [finalHead];
        let processed = 0;
        while (processed < file.size) {
            let currentSize = Math.min(sliceSize, file.size - processed);
            let chunk = new Uint8Array(await file.slice(processed, processed + currentSize).arrayBuffer());
            let blockSize = (algo === 0) ? 16 : 8;
            if ((algo === 0 || algo === 1) && chunk.length % blockSize !== 0) {
                let padLen = blockSize - (chunk.length % blockSize);
                let padded = new Uint8Array(chunk.length + padLen);
                padded.set(chunk);
                padded[padded.length - 1] = padLen; 
                chunk = padded;
            }
            const chunkWA = u8ToWA(chunk);
            let encrypted;
            if (algo === 0) encrypted = wordToUint8(CryptoJS.AES.encrypt(chunkWA, dataKeyWA, { iv: initialIvWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }).ciphertext);
            else if (algo === 1) encrypted = wordToUint8(CryptoJS.TripleDES.encrypt(chunkWA, u8ToWA(dataKeyRaw.slice(0, 24)), { iv: initialIvWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }).ciphertext);
            else if (algo === 2) {
                const md5Full = CryptoJS.MD5(pwdInput).toString(CryptoJS.enc.Hex).toUpperCase();
                const finalKey = md5Full.substr(8, 16); 
                const finalKeyWA = CryptoJS.enc.Utf8.parse(finalKey);
                encrypted = wordToUint8(CryptoJS.RC4.encrypt(chunkWA, finalKeyWA).ciphertext);
            }
            else if (algo === 3) {
                const originalPwdBytes = new TextEncoder().encode(pwdInput);
                encrypted = dataXor(chunk, originalPwdBytes);
            }
            
            encryptedChunks.push(encrypted);
            processed += currentSize;
            progress.style.width = Math.round((processed / file.size) * 100) + "%";
        }
        
        const customName = document.getElementById('customName').value;
        const outName = customName ? `${customName}.KazaneCrypto` : `${file.name}.KazaneCrypto`;
        saveFile(new Blob(encryptedChunks), outName);
        logger("加密任务成功完成");
    } catch (e) { logger("错误: " + e.message); }
}

async function runDecrypt(file, pwdInput) {
    const ansiDecoder = new TextDecoder('gbk');
    try {
        const headUint8 = new Uint8Array(await file.slice(0, 77).arrayBuffer());
        const headDataLen = headUint8[12];
        const encryptedHead = headUint8.slice(13, 13 + headDataLen);
        const headerKeyWA = u8ToWA(formatKey(pwdInput, 32, 48));
        const headerIvWA = u8ToWA(new Uint8Array([56, 48, 50, 52, 75, 83, 65, 50, 52, 54, 56, 79, 87, 69, 54, 56]));

        const decryptedHeadWA = CryptoJS.AES.decrypt({ ciphertext: u8ToWA(encryptedHead) }, headerKeyWA, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding, iv: headerIvWA });
        let dHead = wordToUint8(decryptedHeadWA);
        const fileIvStr = ansiDecoder.decode(dHead.slice(0, 16)).replace(/\0/g, '').trim(); 
        const finalIvWA = u8ToWA(new TextEncoder().encode(fileIvStr));
        const targetMd5Str = ansiDecoder.decode(dHead.slice(16, 48)).replace(/\0/g, '').trim().toLowerCase();
        const algo = dHead[48] | (dHead[49] << 8) | (dHead[50] << 16) | (dHead[51] << 24);
        
        if (algo === 4) {
            return logger("ChaCha20 暂不支持网页解密。");
        }

        const fmtLen = dHead[52] | (dHead[53] << 8) | (dHead[54] << 16) | (dHead[55] << 24);
        const format = ansiDecoder.decode(dHead.slice(56, 56 + fmtLen)).replace(/\0/g, '');

        const dataKeyRaw = formatKey(pwdInput, 32, 0);
        const dataKeyWA = u8ToWA(dataKeyRaw);
        const dataOffset = 13 + headDataLen;
        const totalSize = file.size - dataOffset;
        let processed = 0, isFirstChunk = true, decryptedChunks = [];

        while (processed < totalSize) {
            let sliceSize = Math.min(5 * 1024 * 1024, totalSize - processed);
            const chunk = new Uint8Array(await file.slice(dataOffset + processed, dataOffset + processed + sliceSize).arrayBuffer());
            const chunkWA = u8ToWA(chunk);
            let decrypted;

            if (algo === 0) decrypted = wordToUint8(CryptoJS.AES.decrypt({ ciphertext: chunkWA }, dataKeyWA, { iv: finalIvWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }));
            else if (algo === 1) decrypted = wordToUint8(CryptoJS.TripleDES.decrypt({ ciphertext: chunkWA }, u8ToWA(dataKeyRaw.slice(0, 24)), { iv: finalIvWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }));
            else if (algo === 2) {
                const md5Full = CryptoJS.MD5(pwdInput).toString(CryptoJS.enc.Hex).toUpperCase();
                const finalKeyText = md5Full.substr(8, 16); 
                const finalKeyWA = CryptoJS.enc.Utf8.parse(finalKeyText);
                decrypted = wordToUint8(CryptoJS.RC4.decrypt({ ciphertext: chunkWA }, finalKeyWA));
            }
            else if (algo === 3) {
                const originalPwdBytes = new TextEncoder().encode(pwdInput);
                decrypted = dataXor(chunk, originalPwdBytes);
            }

            if (processed + sliceSize >= totalSize && (algo === 0 || algo === 1)) {
                let blockSize = (algo === 0) ? 16 : 8;
                let padLen = decrypted[decrypted.length - 1];
                if (padLen > 0 && padLen <= blockSize) decrypted = decrypted.slice(0, decrypted.length - padLen);
            }

            if (isFirstChunk) {
                if (CryptoJS.MD5(u8ToWA(decrypted)).toString().toLowerCase() !== targetMd5Str) return logger("校验失败：密码错误");
                isFirstChunk = false;
            }
            decryptedChunks.push(decrypted);
            processed += sliceSize;
            progress.style.width = Math.round((processed / totalSize) * 100) + "%";
        }

        const customName = document.getElementById('customName').value;
        let finalName;
        if (customName) {
            finalName = customName.toLowerCase().endsWith(`.${format.toLowerCase()}`) ? customName : `${customName}.${format}`;
        } else {
            finalName = file.name.replace(/\.kazanecrypto$/i, '') + '.' + format;
        }

        saveFile(new Blob(decryptedChunks), finalName);
        logger("解密任务成功完成");
    } catch (e) { logger("错误: " + e.message); }
}

// 移动端专用下载触发逻辑
function saveFile(blob, name) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const dataUrl = e.target.result;
        
        // 检查浏览器是否支持 Web Share API (部分现代安卓系统 WebView 支持)
        if (navigator.share) {
            const file = new File([blob], name, { type: blob.type });
            navigator.share({
                files: [file],
                title: '保存加密文件',
                text: '这是您生成的加密文件',
            }).then(() => {
                logger("分享成功，文件已保存。");
            }).catch((err) => {
                // 如果分享失败，降级到显示手动保存区域
                showManualArea(dataUrl, name);
            });
        } else {
            showManualArea(dataUrl, name);
        }
    };
    reader.readAsDataURL(blob);
}

function showManualArea(dataUrl, name) {
    const logBox = document.getElementById('log');
    const div = document.createElement('div');
    div.style.cssText = "padding:15px; background:#22c55e; color:white; border-radius:8px; margin:10px 0; text-align:center;";
    div.innerHTML = `<p style="margin:0 0 10px 0">点击或长按下方按钮保存</p>
                     <a href="${dataUrl}" download="${name}" style="color:white; font-weight:bold; word-break:break-all;">【保存: ${name}】</a>`;
    logBox.parentNode.insertBefore(div, logBox);
    logger("由于权限限制，请使用上方的绿色区域进行保存。");
}