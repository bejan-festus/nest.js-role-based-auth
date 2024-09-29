import crypto from 'crypto';

export function encrypt(text: string, iv: string, algorithm: string, key: string) {        
    const ivBuffer = Buffer.from(iv, 'hex');
    const cipher = crypto.createCipheriv(algorithm, key, ivBuffer);
    const encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}
