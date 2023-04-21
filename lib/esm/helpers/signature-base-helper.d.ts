import { Config } from '..';
/**
 * Generates the base string.
 *
 * @param {any} headers The HTTP request headers.
 * @param {Config} config The config.
 * @returns {string} baseString The base string.
 */
declare function generateBase(headers: any, config: Config): string;
/**
 * Generates the base string for validation.
 *
 * @param {any} headers The HTTP request headers.
 * @param {Config} config The config.
 * @returns {string} baseString the base string.
 * @throws {Error} incase of an error.
 */
declare function calculateBase(headers: any, config: Config): string;
/**
 * Returns the current UNIX timestamp.
 *
 * @returns {number} The unix timestamp.
 */
declare function getUnixTimestamp(): number;
export { calculateBase, generateBase, getUnixTimestamp };
