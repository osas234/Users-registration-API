import { ApolloServer } from '@apollo/server';
import { gql } from 'graphql-tag';
import pool from './db.js';

const typeDefs = gql`
    type User {
        id: ID!
        username: String!
        email: String!
    }

    type Query {
        users: [User]
    }
`;

const resolvers = {
    Query: {
        users: async () => {
            const [rows] = await pool.query('SELECT id, username, email FROM users');
            return rows;
        }
    }
};

const server = new ApolloServer({ typeDefs, resolvers });

export default server;