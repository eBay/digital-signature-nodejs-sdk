import { SignatureComponents } from "./SignatureComponents";
export interface Config {
    digestAlgorithm: string;
    jwe: string;
    jwtExpiration: number;
    jweHeaderParams: object;
    jwtPayload: object;
    masterKey: string;
    privateKey: string;
    publicKey: string;
    signatureComponents: SignatureComponents;
    signatureParams: Array<string>;
}
