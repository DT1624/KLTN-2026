import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Protected from "./components/Protected";
import Home from "./pages/Home";
import WalletPage from "./pages/Wallet";
import Holder from "./pages/Holder";
import Issuer from "./pages/Issuer";
import Verifier from "./pages/Verifier";
import Verify from "./pages/Verify";
import Admin from "./pages/Admin";
import Account from "./pages/Account";
import Root from "./pages/Root";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="wallet" element={<WalletPage />} />
        <Route path="account" element={<Protected><Account /></Protected>} />
        <Route path="verify" element={<Verify />} />
        <Route path="verify/:token" element={<Verify />} />
        <Route path="holder" element={<Protected roles={["holder"]}><Holder /></Protected>} />
        <Route path="issuer" element={<Protected roles={["issuer"]}><Issuer /></Protected>} />
        <Route path="verifier" element={<Protected roles={["verifier", "admin", "root"]}><Verifier /></Protected>} />
        <Route path="admin" element={<Protected roles={["admin", "root"]}><Admin /></Protected>} />
        {/* Không chặn theo vai trò khai trong ví: quyền root do hợp đồng quyết định,
            trang tự kiểm `callerIsRoot` rồi báo rõ nếu không đủ quyền. */}
        <Route path="root" element={<Protected><Root /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
