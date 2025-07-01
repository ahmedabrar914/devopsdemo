pipeline {
  agent any

  environment {
    // JMeter VM details
    JM_VM        = '10.216.33.52'
    JM_USER      = 'hdfcbank'
    JM_PASS      = 'PerfTest@1'
    JM_BIN       = '/home1/jmeter/bin/jmeter.sh'
    JM_SCRIPTS   = '/home1/QK/MBR/scripts'
    JM_RESULTS   = '/home1/QK/MBR/Results'
    JM_HTML      = '/home1/QK/MBR/HTML_Reports'

    // K8s details
    K8S_VM       = '10.216.33.20'
    K8S_USER     = 'hdfcbank'
    K8S_PASS     = 'perf@123'
    NAMESPACE    = 'perf-mc'
    DEPLOYMENT   = 'user-profile-v1'
    APP_LABEL    = 'user-profile-v1'

    GEN_FILE     = 'last_deploy_generation.txt'
    JM_REPORT_DIR = ''
  }

  stages {
    stage('Check for New Deployment') {
      steps {
        script {
          def currentGeneration = sh(
            script: """
              sshpass -p '${K8S_PASS}' ssh -o StrictHostKeyChecking=no ${K8S_USER}@${K8S_VM} \\
                "kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o=jsonpath='{.metadata.generation}'"
            """,
            returnStdout: true
          ).trim()

          echo "Current deployment generation: ${currentGeneration}"

          def lastGeneration = ''
          if (fileExists(env.GEN_FILE)) {
            lastGeneration = readFile(env.GEN_FILE).trim()
          }
          echo "Last seen generation: ${lastGeneration}"

          if (currentGeneration == lastGeneration) {
            echo "No new deployment detected. Exiting pipeline."
            currentBuild.result = 'SUCCESS'
            error("No new deployment. Stopping.")
          } else {
            echo "New deployment detected. Proceeding..."
            writeFile(file: env.GEN_FILE, text: currentGeneration)
          }
        }
      }
    }

    stage('Wait for Pods to be Running and Ready') {
      steps {
        script {
          timeout(time: 10, unit: 'MINUTES') {
            waitUntil {
              def podStatus = sh(
                script: """
                  sshpass -p '${K8S_PASS}' ssh -o StrictHostKeyChecking=no ${K8S_USER}@${K8S_VM} '
                    kubectl get pods -n ${NAMESPACE} -l app=${APP_LABEL} -o json
                  '
                """,
                returnStdout: true
              ).trim()
              def json = new groovy.json.JsonSlurper().parseText(podStatus)
              def notReady = []
              for (pod in json.items) {
                def phase = pod.status.phase
                def allReady = pod.status.containerStatuses?.every { it.ready }
                if (phase != 'Running' || !allReady) {
                  notReady << pod.metadata.name
                }
              }
              if (notReady) {
                echo "Pods not yet Running and Ready: ${notReady.join(', ')}"
                return false
              } else {
                echo "✅ All pods for app=${APP_LABEL} are Running and Ready"
                return true
              }
            }
          }
        }
      }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Run JMeter on Remote VM') {
      steps {
        script {
          def jmxName   = 'testplan.jmx'
          def remoteJmx = "${JM_SCRIPTS}/${jmxName}"
          def remoteJtl = "${JM_RESULTS}/${jmxName.replace('.jmx','.jtl')}"
          def reportDir = "${JM_HTML}/${jmxName.replace('.jmx','')}"
          env.JM_REPORT_DIR = reportDir

          // Copy JMX file to JMeter VM
          sh """
            sshpass -p '${JM_PASS}' scp -o StrictHostKeyChecking=no \\
              ${jmxName} \\
              ${JM_USER}@${JM_VM}:${remoteJmx}
          """

          // Run JMeter test remotely
          sh """
            sshpass -p '${JM_PASS}' ssh -o StrictHostKeyChecking=no ${JM_USER}@${JM_VM} '
              rm -rf ${reportDir} &&
              ${JM_BIN} -f -n \\
                -t ${remoteJmx} \\
                -l ${remoteJtl} \\
                -e -o ${reportDir}
            '
          """

          // List output files (debug)
          sh """
            sshpass -p '${JM_PASS}' ssh -o StrictHostKeyChecking=no ${JM_USER}@${JM_VM} '
              echo "→ JTL file:"; ls -lh ${remoteJtl} || echo "   MISSING!"
              echo "→ HTML report dir:"; ls -l ${reportDir} || echo "   MISSING!"
            '
          """
        }
      }
    }

    stage('Fetch JMeter HTML Report') {
      steps {
        script {
          sh """
            rm -rf reports/output
            mkdir -p reports
            sshpass -p '${JM_PASS}' scp -o StrictHostKeyChecking=no -r \\
              ${JM_USER}@${JM_VM}:${JM_REPORT_DIR} reports/output
          """
        }
      }
    }

    stage('Serve HTML Report') {
      steps {
        script {
          def port = 8888
          def reportPath = "${env.WORKSPACE}/reports/output"

          // Kill any previous server
          sh "fuser -k ${port}/tcp || true"

          // Start the Python server in background
          sh """
            cd ${reportPath}
            nohup python3 -m http.server ${port} > /tmp/jmeter_http.log 2>&1 &
          """

          // Get agent IP (first IP from hostname -I)
          def agentIp = sh(
            script: "hostname -I | awk '{print \$1}'",
            returnStdout: true
          ).trim()

          echo "=================================================="
          echo " JMeter HTML Report available at:"
          echo " http://${agentIp}:${port}/"
          echo "=================================================="
        }
      }
    }
  }
}



stage('Fetch & Publish HTML Report') {
  steps {
    script {
      def reportSubdir = jmxName.replace('.jmx', '')
      sh """
        mkdir -p reports
        sshpass -p '${JM_PASS}' scp -o StrictHostKeyChecking=no -r \
          ${JM_USER}@${JM_VM}:'${REPORT_DIR}' reports/
      """
      publishHTML(target: [
        reportDir: "reports/${reportSubdir}",
        reportFiles: 'index.html',
        reportName: 'JMeter Test Report',
        allowMissing: false,
        keepAll: true,
        alwaysLinkToLastBuild: true,
        escapeUnderscores: false,
        allowJs: true
      ])
      archiveArtifacts artifacts: "reports/${reportSubdir}/**", fingerprint: true
    }
  }
}
