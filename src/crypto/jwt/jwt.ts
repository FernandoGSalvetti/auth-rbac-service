import { JwtDTO, JwtPayload, } from "../../dtos/jwt";
import * as node_crypto from "node:crypto";

const HEADER = { alg: 'HS256', typ: 'JWT' };

export function toBase64Url(value: string) {
    return Buffer.from(value).toString('base64url');
}

export function createHmac(secret: string): node_crypto.Hmac {
    return node_crypto.createHmac('sha256', secret);
}

export function getSigninInput(headerToBase64: string, payloadToBase64: string): string {
    return `${headerToBase64}.${payloadToBase64}`
}

export function getSignatureFromBase64(headerToBase64: string, payloadToBase64: string, secret: string): string {
    const hmac = createHmac(secret);
    const signinInput = getSigninInput(headerToBase64, payloadToBase64);
    return hmac.update(signinInput).digest('base64url')
}

const getTimeStampInSeconds = () =>  Math.floor(Date.now() / 1000);


export function sign(payload: JwtDTO, secret: string, expersInSeconds: number): string {
    try {
        const now = getTimeStampInSeconds();
        const payloadJwt: JwtPayload = {
            ...payload,
            exp: expersInSeconds + now,
            iat: now
        }
        const headerToBase64 = toBase64Url(JSON.stringify(HEADER));
        const payloadToBase64 = toBase64Url(JSON.stringify(payloadJwt));
        const signinInput = getSigninInput(headerToBase64, payloadToBase64);
        const signature = getSignatureFromBase64(headerToBase64, payloadToBase64, secret);
        return `${signinInput}.${signature}`
    } catch (error) {
        throw error
    }
}

function decodePayloadJWT(encodedPayload: string): JwtPayload {
    try {
        if (encodedPayload.trim().length > 0) {
            const payloadJwt: JwtPayload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf-8'));
            return payloadJwt;
        }
        throw new Error();
    } catch (error) {
        throw error;
    }
}

export function verifyJwt(token: string, secret: string): JwtPayload | null {
    try {
        const splitedToken = token.split('.');
        const [encodedHeader, encodedPayload, encodedSignature] = splitedToken;
        
        if ((splitedToken.length < 3 || splitedToken.length > 3)) return null;
        
        const expectedSignature = getSignatureFromBase64(encodedHeader as string, encodedPayload as string, secret);
        const bufferedEncondedSignature = Buffer.from(encodedSignature || '');
        const bufferedExpectedSignature = Buffer.from(expectedSignature || '');

        if(bufferedEncondedSignature.length !== bufferedExpectedSignature.length) return null;
        
        const isValid = node_crypto.timingSafeEqual(bufferedEncondedSignature, bufferedExpectedSignature);
        
        if(!isValid) return null;
        
        const payloadJwt = decodePayloadJWT(encodedPayload || '');
        
        if(getTimeStampInSeconds() >= payloadJwt.exp) return null;

        return payloadJwt;
    } catch (error) {
        return null
    }
}