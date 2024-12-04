import expressCors from 'cors';
import config from '../../../../config.json';
import { wrapExpressHandler } from './wrapExpressHandler';

export const cors = wrapExpressHandler(expressCors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'] }));
