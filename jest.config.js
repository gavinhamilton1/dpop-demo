// jest.config.js
export default {
    testEnvironment: 'node',
    setupFilesAfterEnv: ['<rootDir>/test/jest.setup.js'],
    moduleNameMapper: {
      '^/src/(.*)$': '<rootDir>/src/$1'
    },
    transform: {}, // run ESM directly
    collectCoverage: true,
    collectCoverageFrom: ['src/**/*.js'],
  };
  
  