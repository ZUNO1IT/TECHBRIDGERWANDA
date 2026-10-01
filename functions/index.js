javascript
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineString } = require("firebase-functions/params");
const admin = require("firebase-admin");

admin.initializeApp();

const db = admin.firestore();
const auth = admin.auth();

// This UID will be configured securely through Firebase Functions.
// Do NOT put your UID or service-account credentials in frontend code.
const BOOTSTRAP_ADMIN_UID = defineString("BOOTSTRAP_ADMIN_UID");

exports.bootstrapAdmin = onCall(async (request) => {
  // User must be logged in.
  if (!request.auth) {
    throw new HttpsError(
      "unauthenticated",
      "You must be signed in."
    );
  }

  const currentUid = request.auth.uid;
  const allowedUid = BOOTSTRAP_ADMIN_UID.value();

  // Only the configured account can become the first admin.
  if (!allowedUid || currentUid !== allowedUid) {
    throw new HttpsError(
      "permission-denied",
      "This account is not authorized to become an admin."
    );
  }

  // Give the authenticated user the secure Firebase Admin claim.
  await auth.setCustomUserClaims(currentUid, {
    admin: true
  });

  // Synchronize the user's Firestore profile.
  await db.collection("users").doc(currentUid).set(
    {
      uid: currentUid,
      role: "admin",
      accountStatus: "active",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    },
    {
      merge: true
    }
  );

  return {
    success: true,
    message: "Admin claim successfully assigned."
  };
});

