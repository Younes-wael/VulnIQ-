import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Home          from './pages/Home'
import Chat          from './pages/Chat'
import Search        from './pages/Search'
import Dashboard     from './pages/Dashboard'
import Advisor       from './pages/Advisor'
import StackAnalysis from './pages/StackAnalysis'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/"         element={<Home />} />
          <Route path="/chat"     element={<Chat />} />
          <Route path="/search"   element={<Search />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/advisor"  element={<Advisor />} />
          <Route path="/stack"    element={<StackAnalysis />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
