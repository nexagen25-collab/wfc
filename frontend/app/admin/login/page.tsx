import MockGate from "@/components/MockGate";
import LoginForm from "@/components/LoginForm";
export default function AdminLoginPage() {
  return <MockGate area="Admin"><LoginForm role="admin" /></MockGate>;
}
