// Test cases for smartvuln-request-data-code-execution
import vm from 'vm'

export function b2b () {
  return ({ body }: Request, res: Response) => {
    const orderLinesData = body.orderLinesData || ''
    const sandbox = { safeEval, orderLinesData }
    // ruleid: smartvuln-request-data-code-execution
    vm.createContext(sandbox)
  }
}

function direct (req: any) {
  // ruleid: smartvuln-request-data-code-execution
  eval(req.query.expr)
}

function serverGenerated () {
  const expression = '1+2*3'
  // ok: smartvuln-request-data-code-execution
  return eval(expression)
}

function parsedNotEvaluated (req: any) {
  // ok: smartvuln-request-data-code-execution
  return JSON.parse(req.body.data)
}
