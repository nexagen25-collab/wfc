import MockGate from "@/components/MockGate";
import LoginForm from "@/components/LoginForm";
export default function StaffLoginPage() {
  return <MockGate area="Staff"><LoginForm role="staff" /></MockGate>;
}
