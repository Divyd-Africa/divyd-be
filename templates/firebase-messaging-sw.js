// firebase-messaging-sw.js
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-messaging-compat.js");

// 🔥 Your Firebase config (must match index.html)
const firebaseConfig = {
  apiKey: "AIzaSyCL68x6i42NOHM_9Cost5SoWUuBq5604WM",
  authDomain: "testing-divyd.firebaseapp.com",
  projectId: "testing-divyd",
  storageBucket: "testing-divyd.firebasestorage.app",
  messagingSenderId: "706517445001",
  appId: "1:706517445001:web:787b727a514d1734719958",
  measurementId: "G-JKWP4VR9SJ"
}
;

firebase.initializeApp(firebaseConfig);

// Initialize messaging
const messaging = firebase.messaging();

// Handle background messages (so notifications actually appear)
messaging.onBackgroundMessage((payload) => {
  console.log("📩 Background message received: ", payload);

  self.registration.showNotification(payload.notification.title, {
    body: payload.notification.body,
    icon: "/firebase-logo.png", // optional
  });
});
