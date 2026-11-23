import { z } from 'zod';
export const assetSchema = z.object({code:z.string().trim().min(1,'Ingresa un código'), name:z.string().trim().min(1,'Ingresa un nombre'), description:z.string(), unit_id:z.string()});
