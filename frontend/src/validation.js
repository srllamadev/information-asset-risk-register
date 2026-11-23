import { z } from 'zod';
export const assetSchema = z.object({
  code:z.string().trim().min(1,'Ingresa un código').max(80),
  name:z.string().trim().min(1,'Ingresa un nombre').max(200),
  description:z.string().max(10000),
  unit_id:z.string(),
  asset_type:z.string().max(100).optional(),
  category:z.string().max(150).optional(),
  subcategory:z.string().max(150).optional(),
  process:z.string().max(200).optional(),
  owner:z.string().max(200).optional(),
  custodian:z.string().max(200).optional(),
  responsible:z.string().max(200).optional(),
  location:z.string().max(200).optional(),
  classification:z.string().max(100).optional(),
  review_date:z.string().optional(),
  observations:z.string().max(10000).optional(),
});
