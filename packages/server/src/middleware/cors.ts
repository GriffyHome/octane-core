import expressCors from 'cors';
import config from '../../../../config.json';
import { wrapExpressHandler } from './wrapExpressHandler';
import { NextApiRequest, NextApiResponse } from 'next';

// Define the cors function
export const cors = async (req: NextApiRequest, res: NextApiResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        res.status(204).end(); // Respond to preflight request
        return;
    }
};
