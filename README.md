# Zap ⚡ - Secure Credential Manager

Zap is a state-of-the-art secure credential manager designed to help you manage your credentials with confidence. Leveraging blockchain technology and AES encryption, Zap ensures the safety of your sensitive data while providing a user-friendly interface. Whether you need to generate strong passwords, securely store your credentials, or retrieve them when needed, Zap has got you covered.

---

## 🌟 Features

### 🔒 Blockchain Integration
- Credentials are hashed using Ethereum’s Keccak256 algorithm and securely stored on the Ethereum blockchain.
- Immutability ensures your data is tamper-proof and transparent.

### 🔐 AES Encryption
- Data is encrypted at rest using AES-256 to ensure robust security.
- Decryption occurs locally, ensuring your data remains private.

### 👨‍💻 User-Friendly Interface
- Intuitive blue-and-black-themed design to make navigation easy and visually appealing.
- Responsive design ensures seamless use on all devices.

### 💪 Password Strength Indicator
- Real-time feedback on password strength while creating or updating credentials.
- Ensures passwords meet strong security standards.

### 🔑 Password Recovery
- Simple and secure password reset functionality.
- Forgot your password? Reset it with just a few clicks!

### 📊 Real-Time Insights
- Gain insights into credential usage and activity with a Kibana-style dashboard (upcoming feature).

---

## 🚀 Getting Started

Follow these steps to set up and run Zap on your local machine.

### Prerequisites
- Python 3.7+
- Node.js (for additional frontend features)
- MetaMask wallet (for Ethereum blockchain interaction)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Zap-Secure-Credential-Manager.git
   cd Zap-Secure-Credential-Manager
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the `.env` file:
   - Create a `.env` file in the project root.
   - Add the following variables:
     ```env
     FLASK_APP=app.py
     FLASK_ENV=development
     SECRET_KEY=your_secret_key
     INFURA_PROJECT_ID=your_infura_project_id
     CONTRACT_ADDRESS=your_contract_address
     PRIVATE_KEY=your_private_key
     ```

5. Start the Flask application:
   ```bash
   python app.py
   ```

6. Access the app in your browser:
   - Navigate to `http://127.0.0.1:5000`.

---

## 🔧 Technologies Used

| Technology         | Purpose                                   |
|--------------------|-------------------------------------------|
| Flask              | Backend framework                        |
| Web3.py            | Ethereum blockchain interaction          |
| Cryptography       | AES encryption                           |
| HTML/CSS           | Frontend design                          |
| MetaMask           | Wallet for blockchain transactions       |
| PostgreSQL         | Database for storing user credentials    |

---

## 📂 Project Structure

```plaintext
Zap-Secure-Credential-Manager/
├── app.py                  # Main Flask application
├── templates/              # HTML templates
│   ├── base.html           # Base layout
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── home.html           # Dashboard
│   ├── forgot_password.html# Password reset page
├── static/                 # Static files (CSS, JS, images)
│   ├── style.css           # Stylesheet
├── generate_hash.py        # Script for generating hashes
├── CredentialHashes.sol    # Ethereum smart contract
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

---

## 🛠️ Deployment

### Deploying Locally
1. Ensure all dependencies are installed.
2. Start the application as described in the [Getting Started](#getting-started) section.

### Automating Deployment with GitHub Actions
Zap includes a GitHub Actions workflow to automate testing and deployment:

1. Create a `.github/workflows/deploy.yml` file:
   ```yaml
   name: Deploy to Heroku

   on:
     push:
       branches:
         - main

   jobs:
     deploy:
       runs-on: ubuntu-latest

       steps:
         - name: Checkout code
           uses: actions/checkout@v3

         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.9'

         - name: Install dependencies
           run: |
             python -m pip install --upgrade pip
             pip install -r requirements.txt

         - name: Deploy to Heroku
           env:
             HEROKU_API_KEY: ${{ secrets.HEROKU_API_KEY }}
           run: |
             heroku create zap-app
             git push heroku main
   ```

2. Add your Heroku API key to GitHub Secrets.

3. Push changes to the `main` branch, and GitHub Actions will handle the deployment.

---

## 🔌 Browser Extension

A Chrome extension for autofilling credentials is available in the `extension` folder. Follow the [installation guide](extension/README.md) to get started.

## 🤝 Contributing

We welcome contributions! Here’s how you can get involved:

1. Fork the repository.
2. Create a new branch for your feature/bug fix.
3. Commit your changes and push them to your branch.
4. Open a pull request with a detailed description of your changes.

---

## 📜 License

Zap is licensed under the MIT License. See `LICENSE` for details.

---

## 📞 Contact

If you have any questions or feedback, please reach out at:
- Email: <a href="mailto:samsonjoh73@gmail.com">Send me an email</a>
- GitHub Issues: [Zap Issues](https://github.com/samjo2/Zap-Secure-Credential-Manager/issues)

---

Enjoy using **Zap ⚡** - your secure credential management solution!
