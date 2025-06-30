import request from 'supertest';
import app from '../index.js';

describe('Auth Routes', () => {
    it('should sign up a new user', async () => {
        const res = await request(app).post('/auth/signup').send({
            username: 'testuser',
            email: 'testuser@gmail.com',
            password: 'Test@123',
            confirmPassword: 'Test@123'
        });
        expect(res.statusCode).toBe(201);
        expect(res.body.msg).toBe('Signup successful');
    });
});