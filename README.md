<img src="https://raw.githubusercontent.com/dwndlnd/Chapter.Net.Security/master/Icon.png" alt="logo" width="64"/>

# Chapter.Net.Security Library

## Overview
Chapter.Net.Security provides ways to secure data and strings.

## Features
- **Hshing:** Generates salts and hashes data on multiple ways.
- **XML Signing:** Signs and verifies XML structures with a given key.
- **Tokening:** Generates token to verify communications and more.

## Getting Started

1. **Installation:**
    - Install the Chapter.Net.Security library via NuGet Package Manager:
    ```bash
    dotnet add package Chapter.Net.Security
    ```

2. **Hashing:**
    - Usage
    ```csharp
    public void ViewModel : ObservableObject
    {
        public IHashing _hashing;

        public ViewModel(IHashing hashing)
        {
            _hashing = hashing;
        }

        public string SavePassword(string userName, string password)
        {
            var data = _hashing.GenerateSecureHash(password);
            using var userRepo = Context.GetRepo<UserRepository>();
            var entity = userRepo.GetUser(userName);
            entity.Password = data.Value;
            entity.Salt = data.Salt;
            userRepo.SubmitChanges();
        }

        public bool ValidatePassword(string userName, string password)
        {
            using var userRepo = Context.GetRepo<UserRepository>();
            var entity = userRepo.GetUser(userName);
            var hashedPassword = _hashing.GenerateSecureHash(password, entity.Salt);
            return hashedPassword == entity.Password;
        }
    }
    ```

3. **XML Signing:**
    - Write an XML file signed
    ```csharp
    private void WriteSignedData(Data data, string filePath)
    {
        var options = new SignedXmlOptions
        {
            Algo = GetKey(),
            WriteIndented = true
        };

        var writer = new SignedXmlWriter(options);
        writer.Write(data, filePath);
    }

    private AsymmetricAlgorithm GetKey()
    {
        // The key used for write, must be used for read.
        var keyString = "<RSAKeyValue><Modulus>xo6kQb......";
        var key = new RSACryptoServiceProvider();
        key.FromXmlString(keyString);
    }
    ```
    - Read and Verify an signed XML file
    ```csharp
    private Data ReadSignedFile(string filePath)
    {
        var options = new SignedXmlOptions
        {
            Algo = GetKey(),
            AllowReadInvalid = true
        };
    
        var reader = new SignedXmlReader(options);
        reader.ReadFile(filePath, out Data data);
        return data;
    }
    
    private AsymmetricAlgorithm GetKey()
    {
        // The key used for write, must be used for read.
        var keyString = "<RSAKeyValue><Modulus>xo6kQb......";
        var key = new RSACryptoServiceProvider();
        key.FromXmlString(keyString);
    }
    ```

4. **Tokening:**
    - Usage
    ```csharp
    public void ViewModel : ObservableObject
    {
        public ITokenGenerator _tokenGenerator;

        public ViewModel(ITokenGenerator tokenGenerator)
        {
            _tokenGenerator = tokenGenerator;
        }

        public string GetNewToken(string userName)
        {
            using var userRepo = Context.GetRepo<UserRepository>();
            var entity = userRepo.GetUser(userName);
            return entity.IsActive() ? _tokenGenerator.Generate(64) : null;
        }
    }
    ```

## Links
* [NuGet](https://www.nuget.org/packages/Chapter.Net.Security)
* [GitHub](https://github.com/dwndlnd/Chapter.Net.Security)

## License
Copyright (c) David Wendland. All rights reserved.
Licensed under the MIT License. See LICENSE file in the project root for full license information.
