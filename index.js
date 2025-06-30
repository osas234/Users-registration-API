import express from 'express';
import morgan from 'morgan';
import logger from './logger.js';
import authRoutes from './Routes/authRoutes.js';
import userRoutes from './Routes/userRoutes.js';
import profileRoutes from './Routes/profileRoutes.js';
import dotenv from 'dotenv';
dotenv.config();
import limiter from './Middleware/rateLimiter.js';
import server from './graphql.js';
import { expressMiddleware } from '@apollo/server/express4';
import path from 'path';
import { fileURLToPath } from 'url';
import errorHandler from './Middleware/errorHandler.js';
import helmet from 'helmet';
import cors from 'cors';
import './validateEnv.js';
import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';
import pool from './db.js';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(helmet());

// Logging middleware
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url}`);
    next();
});
app.use(morgan('dev'));

// Swagger setup
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'practice API', version: '1.0.0' },
    },
    apis: ['./Routes/*.js'],
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);
app.use('/profile', profileRoutes);

// Rate limiter and error handler 
app.use(limiter);
app.use(errorHandler);

const PORT = process.env.PORT || 8080;

(async () => {
    await server.start();
    app.use('/graphql', expressMiddleware(server));
    
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
    app.listen(PORT, () => {
        console.log(`Server is running on port http://localhost:${PORT}`);
    });
})();

export default app;