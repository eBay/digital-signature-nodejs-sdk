import { Config } from '..';
/**
 * Decrypts the input JWE string and returns the 'pkey' value from claims set.
 *
 * @param {string} jweString The JWE string.
 * @param {Config} config The input config.
 * @returns Promise<string> If the JWE decryption is successful, else returns Promise<undefined>.
 */
export declare function decryptJWE(jweString: string, config: Config): Promise<string | undefined>;
/**
 * Generates JWE string.
 *
 * @param {Config} config The input config.
 * @returns {Promise<string>} jwe The JWE as string.
 */
export declare function encryptJWE(config: Config): Promise<string>;
