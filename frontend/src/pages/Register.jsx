import { Link } from 'react-router-dom'
import Navbar from '../components/Navbar.jsx'

export default function Register() {
  return <>
    <Navbar />
    <main style={{ padding: '7rem 1.5rem', maxWidth: 640, margin: '0 auto' }}>
      <h1 style={{ fontSize: 24, color: '#00d4ff' }}>Administrator-provisioned access</h1>
      <p style={{ margin: '1rem 0' }}>Public registration is disabled. Contact your SentinelAI administrator to request an account.</p>
      <Link to="/login" style={{ color: '#00d4ff' }}>Sign in with your provisioned account</Link>
    </main>
  </>
}
