module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: ['airbnb-base', 'plugin:prettier/recommended'],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'prettier/prettier': [
      'error',
      {
        useTabs: false,
        endOfLine: 'auto',
      },
    ],

    'react/prop-types': 'off',

    'import/no-extraneous-dependencies': [
      'error',
      {
        devDependencies: false,
        optionalDependencies: false,
        peerDependencies: false,
        // packageDir: './',
      },
    ],

    'no-new': 'off',
    'no-console': 'off',
    'no-alert': 'off',
    'no-plusplus': 'error',
    'no-param-reassign': 'error',
    'no-underscore-dangle': 'off',
    'no-return-assign': 'error',
    'max-depth': ['error', 2],
    // 'max-lines-per-function': ['error', 15],
    'import/extensions': ['off'],
    'import/prefer-default-export': 'off',
    'no-restricted-syntax': ['error', 'ForInStatement', 'LabeledStatement', 'WithStatement'],
  },
  settings: {
    'import/core-modules': ['@apollo/client/link/context'],
  },
};
