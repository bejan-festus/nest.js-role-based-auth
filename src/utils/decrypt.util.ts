import crypto from 'crypto';

export function decrypt(encrypted: string, iv: string, algorithm: string, key: string) {
    const ivBuffer = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuffer);
    const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    return decrypted;
}