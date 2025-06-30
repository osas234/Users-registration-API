import Joi from 'joi';
import dotenv from 'dotenv';
dotenv.config();

const envSchema = Joi.object({
    JWT_SECRET: Joi.string().required(),
    JWT_REFRESH_SECRET: Joi.string().required(),
    DB_USER: Joi.string().required(),
    DB_HOST: Joi.string().required(),
    DB_NAME: Joi.string().required(),
    DB_PASSWORD: Joi.string().required(),
    SENDGRID_API_KEY: Joi.string().required(),
    SENDGRID_EMAIL: Joi.string().required(),
    PORT: Joi.string().optional()
}).unknown();

const { error } = envSchema.validate(process.env);
if (error) {
    throw new Error(`Environment validation error: ${error.message}`);
}